# The rmw_zenoh counterpart of the rmw profile. The baseline is generate_configs output, unedited.

import re
import shutil
import tempfile
from pathlib import Path
from xml.etree import ElementTree as ET

from ..keystore import Keystore
from ..posture import Posture
from ..process import chmod, run

ROUTER_FILE = "zenohd.json5"
ROUTER_ENCLAVE = "/zenohd"


def _templates() -> tuple[Path, Path]:
    """The default session and router configs rmw_zenoh_cpp ships."""
    prefix = Path(run("ros2", "pkg", "prefix", "rmw_zenoh_cpp", quiet=True).strip())
    config = prefix / "share" / "rmw_zenoh_cpp" / "config"
    return (config / "DEFAULT_RMW_ZENOH_SESSION_CONFIG.json5",
            config / "DEFAULT_RMW_ZENOH_ROUTER_CONFIG.json5")


def _policy(ks: Keystore) -> Path:
    """The policy the enclaves were granted from. The shared-enclave posture writes its own."""
    shared = ks.root / "policy-shared.xml"
    return shared if shared.exists() else ks.root / "policy.xml"


def _single_enclave_policies(policy: Path, work: Path) -> list[tuple[str, Path]]:
    """One policy per enclave, because generate_configs only reads the first enclave."""
    found: list[tuple[str, Path]] = []
    paths = [e.get("path", "") for e in ET.parse(policy).getroot().iter("enclave")]
    for index, enclave in enumerate(p for p in paths if p):
        tree = ET.parse(policy)
        container = tree.getroot().find("enclaves")
        if container is None:
            raise ValueError(f"no <enclaves> in {policy}")
        for element in list(container):
            if element.get("path") != enclave:
                container.remove(element)
        out = work / f"policy_{index}.xml"
        tree.write(out)
        found.append((enclave, out))
    return found


def mutate_zenoh_configs(posture: Posture, ks: Keystore) -> str:
    """generate_configs, once per enclave, into each enclave and the keystore root."""
    if posture.omit_plugins:
        return "no Zenoh configs written, so every process runs on the plaintext defaults"

    session_template, router_template = _templates()
    written: list[str] = []
    with tempfile.TemporaryDirectory() as tmp:
        work = Path(tmp)
        for enclave, policy in _single_enclave_policies(_policy(ks), work):
            out = work / enclave.strip("/").replace("/", "_")
            out.mkdir()
            run("ros2", "run", "zenoh_security_tools", "generate_configs",
                "-p", str(policy), "-e", str(ks.enclaves),
                "-d", str(posture.domain_id),
                "-c", str(session_template), "-r", str(router_template),
                cwd=out, quiet=True)
            sessions = [p for p in out.glob("*.json5") if p.name != ROUTER_FILE]
            if len(sessions) != 1:
                raise SystemExit(f"generate_configs wrote {len(sessions)} session "
                                 f"configs for {enclave}, expected 1")
            destination = ks.enclaves / enclave.strip("/") / posture.profile_name
            shutil.copy2(sessions[0], destination)
            shutil.copy2(out / ROUTER_FILE, ks.root / ROUTER_FILE)
            written.append(enclave)

    # A.4.1, the same as for the DDS profiles: a writable config is a reroutable one.
    mode = 0o666 if posture.profile_writable else 0o444
    first = ks.enclaves / written[0].strip("/") / posture.profile_name
    shutil.copy2(first, ks.root / posture.profile_name)
    if not posture.zenoh_mtls:
        for path in [ks.root / posture.profile_name, ks.root / ROUTER_FILE,
                     *(ks.enclaves / e.strip("/") / posture.profile_name for e in written)]:
            _drop_mtls(path)
    for path in (ks.root / posture.profile_name, ks.root / ROUTER_FILE):
        chmod(path, mode)
    return (f"generate_configs for {len(written)} enclave(s), router config from "
            f"{ROUTER_ENCLAVE}, mTLS {'on' if posture.zenoh_mtls else 'OFF'}, "
            f"config mode={'0666 WRITABLE' if posture.profile_writable else '0444'}")


ENABLE_MTLS = re.compile(r'("?enable_mtls"?\s*:\s*)true')


def _drop_mtls(path: Path) -> None:
    """A.1.1. TLS stays on, so the wire is encrypted, but no peer is asked for a certificate."""
    text, count = ENABLE_MTLS.subn(r"\1false", path.read_text(encoding="utf-8"))
    if count == 0:
        raise SystemExit(f"no enable_mtls: true in {path}, so A.1.1 cannot be set")
    path.write_text(text, encoding="utf-8")

from .grants import Grant, unique_enclaves
from .keystore import Keystore
from .policy import write_policy
from .posture import Posture
from .process import run


def _bound_ca_lifetime(posture: Posture, ks: Keystore) -> None:
    """A.1.9. sros2 issues its CA for 10 years, which cert_days does not reach."""
    cert, key = ks.identity_ca_cert, ks.identity_ca_key
    if not (cert.exists() and key.exists()):
        return
    line = run("openssl", "x509", "-in", str(cert), "-noout", "-subject",
               "-nameopt", "compat", quiet=True).strip()
    subject = line.split("=", 1)[1].strip() if "=" in line else "/CN=sros2CA"
    run("openssl", "req", "-x509", "-new", "-key", str(key.resolve()),
        "-out", str(cert.resolve()), "-days", str(posture.cert_days),
        "-subj", subject, "-sha256",
        "-addext", "basicConstraints=critical,CA:TRUE,pathlen:1", quiet=True)
    print(f"  CA {subject} re-issued with a {posture.cert_days}d lifetime")


def build_baseline(posture: Posture, grants: list[Grant]) -> Keystore:
    ks = Keystore(posture.keystore)
    print("== stage 1, baseline via the sros2 CLI ==")

    ks.root.mkdir(parents=True, exist_ok=True)
    run("ros2", "security", "create_keystore", str(ks.root))
    _bound_ca_lifetime(posture, ks)

    for enclave in unique_enclaves(grants):
        print(f"  create_enclave {enclave}")
        run("ros2", "security", "create_enclave", str(ks.root), enclave, quiet=True)
    if posture.zenoh:
        # generate_configs takes the router's TLS identity from an enclave named zenohd.
        print("  create_enclave /zenohd (the Zenoh router's identity)")
        run("ros2", "security", "create_enclave", str(ks.root), "/zenohd", quiet=True)

    policy = ks.root / "policy.xml"
    write_policy(policy, grants)
    for enclave in unique_enclaves(grants):
        print(f"  create_permission {enclave} (least privilege)")
        run("ros2", "security", "create_permission",
            str(ks.root), enclave, str(policy), quiet=True)

    found = ks.enclave_dirs()
    if not found:
        raise SystemExit(f"sros2 produced no enclaves under {ks.enclaves}")
    print(f"  baseline: {len(found)} enclaves, "
          f"governance signed by {ks.permissions_ca_cert.name}")
    if ks.identity_ca_cert.resolve() == ks.permissions_ca_cert.resolve():
        print("  note: identity CA and permissions CA are the SAME certificate, "
              "which is the sros2 default and the first half of leaf A.3.15")
    return ks

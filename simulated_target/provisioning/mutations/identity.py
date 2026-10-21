# Every mutation takes (posture, keystore, grants) so the registry drives them uniformly.

import os
import shutil
from pathlib import Path

from ..grants import Grant
from ..keystore import Keystore
from ..posture import KeyType, Posture
from ..process import chmod, run


def _reissue_cert(
    ks: Keystore, ed: Path, cn: str, posture: Posture,
) -> None:
    key, cert = ed / "key.pem", ed / "cert.pem"
    if posture.key_type is KeyType.RSA:
        run("openssl", "genrsa", "-out", str(key), str(posture.key_bits), quiet=True)
    else:
        run("openssl", "ecparam", "-name", "prime256v1", "-genkey", "-noout",
            "-out", str(key), quiet=True)
    csr = ed / "req.csr"
    # sros2 issues enclave certificates with a single CN attribute holding the
    # enclave path (keystore/_enclave.py), and its permissions.xsl writes
    # "CN=<path>" into <subject_name>. Fast DDS requires the two to match
    # exactly, so any extra RDN here breaks every node. The '/' in the path is
    # escaped because openssl's -subj uses it as the RDN separator.
    subject = f"/CN={cn.replace('/', chr(92) + '/')}"
    run("openssl", "req", "-new", "-key", str(key), "-out", str(csr),
        "-subj", subject, quiet=True)
    # Without an extension openssl issues X.509 v1, which rustls, and so Zenoh's TLS, refuses.
    extensions = ed / "v3.ext"
    extensions.write_text("basicConstraints=CA:FALSE\n")
    run("openssl", "x509", "-req", "-in", str(csr), "-sha256",
        "-CA", str(ks.identity_ca_cert), "-CAkey", str(ks.identity_ca_key),
        "-CAcreateserial", "-out", str(cert), "-days", str(posture.cert_days),
        "-extfile", str(extensions), quiet=True)
    csr.unlink(missing_ok=True)
    extensions.unlink(missing_ok=True)
    if posture.key_passphrase:
        enc = ed / "key.enc.pem"
        run("openssl", "pkcs8", "-topk8", "-in", str(key), "-out", str(enc),
            "-v2", "aes-256-cbc", "-passout", f"pass:{posture.key_passphrase}",
            quiet=True)
        enc.replace(key)


def mutate_identity(posture: Posture, ks: Keystore, grants: list[Grant]) -> str:  # noqa: ARG001
    """A.1.3, A.1.9 and A.1.10. sros2 fixes the key type at EC prime256v1, the"""
    dirs = ks.enclave_dirs()
    if not dirs:
        return "no enclaves"

    if posture.shared_identity:
        # A.1.3, one identity certificate for every enclave with the same
        # subject DN, so a credential lifted from one node works as any node,
        # and on any robot flashed from the same image.
        first = dirs[0]
        _reissue_cert(ks, first, "/robot", posture)
        for ed in dirs[1:]:
            shutil.copy2(first / "key.pem", ed / "key.pem")
            shutil.copy2(first / "cert.pem", ed / "cert.pem")
        detail = f"ONE identity (CN=/robot) across {len(dirs)} enclaves"
    else:
        for ed in dirs:
            enclave = "/" + str(ed.relative_to(ks.enclaves)).replace(os.sep, "/")
            _reissue_cert(ks, ed, enclave, posture)
        detail = f"{len(dirs)} distinct identities"

    for ed in dirs:
        chmod(ed / "key.pem", posture.mode_key)      # A.1.4
        chmod(ed / "cert.pem", 0o444)
        # A.1.5, the passphrase in cleartext beside the key it protects defeats
        # encryption at rest entirely.
        if posture.key_passphrase and posture.leak_passphrase:
            (ed / "key.pass").write_text(posture.key_passphrase + "\n")
            chmod(ed / "key.pass", 0o644)

    kt = f"RSA-{posture.key_bits}" if posture.key_type is KeyType.RSA else "EC-P256"
    return (f"{detail}, {kt}, {posture.cert_days}d lifetime, key mode "
            f"{posture.key_mode}, passphrase={'set' if posture.key_passphrase else 'none'}"
            f"{', LEAKED beside key' if posture.leak_passphrase else ''}")

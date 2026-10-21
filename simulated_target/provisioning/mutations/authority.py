# Every mutation takes (posture, keystore, grants) so the registry drives them uniformly.

import shutil

from ..grants import Grant
from ..keystore import Keystore
from ..posture import Posture
from ..process import chmod, run


def mutate_separate_ca(posture: Posture, ks: Keystore, grants: list[Grant]) -> str:  # noqa: ARG001
    """A.3.15, hardening direction. sros2 issues one CA and uses it for both"""
    perm_key = ks.private / "permissions_ca.key.pem"
    perm_cert = ks.public / "permissions_ca.cert.pem"

    if ks.identity_ca_cert.resolve() != ks.permissions_ca_cert.resolve():
        return "already separate, nothing to do"

    for p in (perm_cert, perm_key):
        if p.is_symlink():
            p.unlink()

    run("openssl", "ecparam", "-name", "prime256v1", "-genkey", "-noout",
        "-out", str(perm_key), quiet=True)
    run("openssl", "req", "-new", "-x509", "-key", str(perm_key),
        "-out", str(perm_cert), "-days", str(posture.cert_days),
        "-subj", "/CN=sros2PermissionsCA",
        quiet=True)

    for ed in ks.enclave_dirs():
        target = ed / "permissions_ca.cert.pem"
        if target.is_symlink():
            target.unlink()
        shutil.copy2(perm_cert, target)

    chmod(perm_key, 0o400)
    return "distinct Permissions CA generated, enclaves repointed at it"

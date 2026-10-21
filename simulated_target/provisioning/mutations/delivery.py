# Every mutation takes (posture, keystore, grants) so the registry drives them uniformly.

import shutil

from ..grants import Grant
from ..keystore import Keystore
from ..posture import Posture
from ..process import chmod


def mutate_strip_ca_key(posture: Posture, ks: Keystore, grants: list[Grant]) -> str:  # noqa: ARG001
    """A.4.3, hardening direction. `create_keystore` leaves the CA signing keys in"""
    if not ks.private.exists():
        return "already absent"
    shutil.rmtree(ks.private, ignore_errors=True)
    return "keystore/private removed from the deployed keystore"


def mutate_keystore_modes(posture: Posture, ks: Keystore, grants: list[Grant]) -> str:  # noqa: ARG001
    """A.0.3 and A.4.2, the keystore directory's own mode."""
    chmod(ks.root, posture.mode_keystore)
    for d in (ks.public, ks.enclaves):
        if d.exists():
            chmod(d, posture.mode_keystore)
    for ed in ks.enclave_dirs():
        chmod(ed, posture.mode_keystore)
    return f"keystore tree mode {posture.keystore_mode}"

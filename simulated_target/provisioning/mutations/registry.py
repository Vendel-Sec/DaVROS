# Every `applies` predicate takes the posture, even when its answer ignores it.

from collections.abc import Callable

from pydantic import BaseModel

from ..grants import Grant
from ..keystore import Keystore
from ..posture import Posture
from .authority import mutate_separate_ca
from .delivery import mutate_keystore_modes, mutate_strip_ca_key
from .enclaves import mutate_shared_enclave
from .governance import mutate_governance
from .identity import mutate_identity
from .permissions import mutate_permissions
from .profile import mutate_xml_profile


class Mutation(BaseModel):
    """One named edit to the baseline keystore, tagged with the leaf it creates."""
    model_config = {"arbitrary_types_allowed": True}

    name: str
    leaves: list[str]
    describe: str
    applies: Callable[[Posture], bool]
    run: Callable[[Posture, Keystore, list[Grant]], str]


# Order matters. Structure first, then documents, then identities, then the
# things that remove the material later steps need.
MUTATIONS: list[Mutation] = [
    Mutation(
        name="shared_enclave", leaves=["A.3.13"],
        describe="collapse every node into one enclave",
        applies=lambda p: p.shared_enclave, run=mutate_shared_enclave,
    ),
    Mutation(
        name="separate_ca", leaves=["A.3.15"],
        describe="split the single sros2 CA into identity and permissions CAs",
        applies=lambda p: p.separate_ca, run=mutate_separate_ca,
    ),
    Mutation(
        name="governance", leaves=[
            "A.2.2", "A.2.3", "A.2.4", "A.2.5", "A.2.6", "A.2.7", "A.2.8",
            "A.3.2", "A.3.3", "A.3.4", "A.3.5", "A.3.6", "A.3.7", "A.3.8",
            "A.3.9", "A.3.16",
        ],
        describe="rewrite the domain rule and topic rules, then re-sign",
        applies=lambda p: True, run=mutate_governance,  # noqa: ARG005
    ),
    Mutation(
        name="permissions", leaves=[
            "A.3.10", "A.3.11", "A.3.12", "A.3.13", "A.3.14", "A.3.17",
        ],
        describe="rewrite grants below the sros2 policy schema, then re-sign",
        applies=lambda p: True, run=mutate_permissions,  # noqa: ARG005
    ),
    Mutation(
        name="identity", leaves=["A.1.3", "A.1.4", "A.1.5", "A.1.9", "A.1.10"],
        describe="reissue certificates with the requested type, size and lifetime",
        applies=lambda p: True, run=mutate_identity,  # noqa: ARG005
    ),
    Mutation(
        name="xml_profile", leaves=[
            "A.0.5", "A.1.1", "A.1.6", "A.1.7", "A.1.8", "A.2.1", "A.3.1", "A.4.1",
        ],
        describe="author the Fast DDS profile sros2 never writes",
        applies=lambda p: True, run=mutate_xml_profile,  # noqa: ARG005
    ),
    Mutation(
        name="keystore_modes", leaves=["A.0.3", "A.4.2"],
        describe="set the keystore tree's mode",
        applies=lambda p: True, run=mutate_keystore_modes,  # noqa: ARG005
    ),
    # Last: it deletes the CA key every re-signing step above depends on.
    Mutation(
        name="strip_ca_key", leaves=["A.4.3"],
        describe="remove keystore/private from the deployed keystore",
        applies=lambda p: p.strip_ca_key, run=mutate_strip_ca_key,
    ),
]

# Every mutation takes (posture, keystore, grants) so the registry drives them uniformly.

import shutil

from ...robot import graph_spec
from ..grants import Grant
from ..keystore import Keystore
from ..policy import write_policy
from ..posture import Posture
from ..process import run


def mutate_shared_enclave(posture: Posture, ks: Keystore, grants: list[Grant]) -> str:  # noqa: ARG001
    """A.3.13 companion. Per-node segmentation collapses to one identity holding the"""
    merged = Grant.from_spec(graph_spec.merged_node())
    for ed in ks.enclave_dirs():
        shutil.rmtree(ed, ignore_errors=True)
    run("ros2", "security", "create_enclave", str(ks.root), merged.enclave, quiet=True)
    policy = ks.root / "policy-shared.xml"
    write_policy(policy, [merged])
    run("ros2", "security", "create_permission",
        str(ks.root), merged.enclave, str(policy), quiet=True)
    return (f"one enclave /robot holding the union: {len(merged.publish)} publish, "
            f"{len(merged.subscribe)} subscribe")

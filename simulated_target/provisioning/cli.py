import shutil
import sys

from .baseline import build_baseline
from .grants import GRAPH, bridge_grants
from .keystore import Keystore
from .mutations import MUTATIONS
from .posture import Posture


def write_target_env(posture: Posture, ks: Keystore) -> None:
    """The effective runtime environment, so the A.0 leaves can be audited offline"""
    profile = "" if posture.omit_plugins else f"/keystore/{posture.profile_name}"
    if posture.zenoh:
        router = "" if posture.omit_plugins else "/keystore/zenohd.json5"
        profile_line = (f"ZENOH_ROUTER_CONFIG_URI={router}\n"
                        f"ZENOH_SESSION_CONFIG_URI={profile}\n")
    elif posture.cyclone:
        profile_line = f"CYCLONEDDS_URI={'file://' + profile if profile else ''}\n"
    else:
        profile_line = f"FASTRTPS_DEFAULT_PROFILES_FILE={profile}\n"
    (ks.root / "target.env").write_text(
        f"ROS_SECURITY_ENABLE={posture.security_enable}\n"
        f"ROS_SECURITY_STRATEGY={posture.security_strategy}\n"
        f"ROS_SECURITY_KEYSTORE={ks.root}\n"
        f"ROS_SECURITY_ENCLAVE_OVERRIDE={posture.enclave_override}\n"
        f"ROS_DOMAIN_ID={posture.domain_id}\n"
        f"RMW_IMPLEMENTATION={posture.rmw}\n"
        + profile_line
    )


def main() -> int:
    posture = Posture()
    ks_root = posture.keystore

    if ks_root.exists():
        for child in ks_root.iterdir():
            if child.is_dir() and not child.is_symlink():
                shutil.rmtree(child, ignore_errors=True)
            else:
                child.unlink(missing_ok=True)

    grants = list(GRAPH)
    if posture.rosbridge:
        grants += bridge_grants(posture.rosbridge_enclave)
        print(f"B.0.2: rosbridge enabled, granted inside {posture.rosbridge_enclave}")
    ks = build_baseline(posture, grants)

    print("\n== stage 2, mutations against that baseline ==")
    applied = 0
    for mut in MUTATIONS:
        if not mut.applies(posture):
            print(f"  skip  {mut.name:16s} ({', '.join(mut.leaves)})")
            continue
        detail = mut.run(posture, ks, grants)
        print(f"  apply {mut.name:16s} ({', '.join(mut.leaves)})\n"
              f"          {mut.describe}\n"
              f"          -> {detail}")
        applied += 1

    write_target_env(posture, ks)
    shutil.rmtree(ks.root / ".work", ignore_errors=True)
    (ks.root / ".ready").write_text("ok\n")

    print(f"\nprovisioned {len(ks.enclave_dirs())} enclave(s), "
          f"{applied}/{len(MUTATIONS)} mutations applied, keystore at {ks.root}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

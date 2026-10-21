import argparse
import os
import signal
import subprocess
import sys
import time
from pathlib import Path

import rclpy
from pydantic_settings import BaseSettings, SettingsConfigDict

from . import graph_spec
from .nodes import NODE_TYPES

STARTUP_GRACE_S = 6.0
STAGGER_S = 0.4
WATCH_INTERVAL_S = 2.0


class GraphSettings(BaseSettings):
    """What the supervisor needs to know about the posture it is launching under."""
    model_config = SettingsConfigDict(case_sensitive=False, extra="ignore")

    # A.3.13, one enclave for every node instead of one per node.
    target_shared_enclave: bool = False
    # A.0.4, an override that takes precedence over the keystore and --enclave.
    ros_security_enclave_override: str = ""
    # A.0.1 and A.0.2, reported in the startup summary.
    ros_security_enable: str = ""
    ros_security_strategy: str = ""


class ChildSettings(BaseSettings):
    """What a spawned node process is told about itself."""
    model_config = SettingsConfigDict(case_sensitive=False, extra="ignore")

    lab_enclave: str = "?"


def run_one(name: str, argv: list[str]) -> int:
    """Run a single node. This is the child process the supervisor spawns."""
    rclpy.init(args=argv)
    node = NODE_TYPES[name]()
    node.get_logger().info(f"{name} up, enclave={ChildSettings().lab_enclave}")
    try:
        rclpy.spin(node)
    except KeyboardInterrupt:
        pass
    finally:
        node.destroy_node()
        if rclpy.ok():
            rclpy.shutdown()
    return 0


def report_startup(
    settings: GraphSettings,
    children: dict[str, subprocess.Popen],
    started: list[str],
    refused: list[str],
) -> None:
    print("\n" + "=" * 66)
    print(" node startup result")
    print("=" * 66)
    for name in started:
        print(f"  UP      {name}")
    for name in refused:
        print(f"  REFUSED {name}  (exit {children[name].returncode})")

    enabled = settings.ros_security_enable
    strategy = settings.ros_security_strategy
    if enabled.lower() != "true":
        print("\n  Security is OFF (A.0.1). Every node above is talking in the clear.")
    elif refused and strategy == "Enforce":
        print("\n  Nodes refusing to start under Enforce is the control working.")
    elif strategy != "Enforce":
        print(f"\n  Strategy is '{strategy or 'unset'}', so Permissive (A.0.2). A node "
              "with broken\n  security material would start unsecured and say nothing.")
    print("=" * 66 + "\n", flush=True)


def spawn_all(settings: GraphSettings, host: str = "robot") -> dict[str, subprocess.Popen]:
    children: dict[str, subprocess.Popen] = {}
    for spec in graph_spec.NODES:
        if spec.name not in NODE_TYPES:
            print(f"  no implementation for {spec.name}, skipping", flush=True)
            continue
        if spec.host != host:
            print(f"  {spec.name} runs on {spec.host}, not here", flush=True)
            continue
        # A.3.13 and A.0.4: with a shared enclave or an override in force, every
        # node runs under one identity and one grant, so least privilege is gone.
        enclave = (
            graph_spec.SHARED_ENCLAVE if settings.target_shared_enclave
            else spec.enclave
        )
        argv = [
            sys.executable, "-m", "simulated_target.robot.graph", "--node", spec.name,
            "--ros-args", "--enclave", enclave,
        ]
        effective = settings.ros_security_enclave_override or enclave
        env = dict(os.environ, LAB_ENCLAVE=effective)
        # Each node loads its own enclave's rmw profile. The copy at the
        # keystore root is the artefact A.4.1 reads, and it is one enclave's:
        # applying it to every node hands them all the same identity and grant.
        keystore = Path(os.environ.get("ROS_SECURITY_KEYSTORE", "/keystore"))
        enclave_dir = keystore / "enclaves" / effective.strip("/")
        profile = enclave_dir / "fastdds_profile.xml"
        if "FASTRTPS_DEFAULT_PROFILES_FILE" in env and profile.is_file():
            env["FASTRTPS_DEFAULT_PROFILES_FILE"] = str(profile)
        config = enclave_dir / "cyclonedds.xml"
        if env.get("CYCLONEDDS_URI") and config.is_file():
            env["CYCLONEDDS_URI"] = f"file://{config}"
        session = enclave_dir / "zenoh_session.json5"
        if env.get("ZENOH_SESSION_CONFIG_URI") and session.is_file():
            env["ZENOH_SESSION_CONFIG_URI"] = str(session)
        children[spec.name] = subprocess.Popen(argv, env=env)
        time.sleep(STAGGER_S)
    return children


class ShutdownRequested(Exception):
    """Raised out of the SIGTERM and SIGINT handlers to end the watch loop."""


def request_shutdown(signum: int, frame: object) -> None:
    raise ShutdownRequested


def watch(children: dict[str, subprocess.Popen], started: list[str]) -> None:
    """Report node exits until a signal ends it."""
    while True:
        time.sleep(WATCH_INTERVAL_S)
        for name in list(started):
            if children[name].poll() is not None:
                print(f"  node {name} exited with {children[name].returncode}",
                      flush=True)
                started.remove(name)


def stop_children(children: dict[str, subprocess.Popen]) -> None:
    for proc in children.values():
        proc.terminate()
    for proc in children.values():
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()


def supervise(settings: GraphSettings, host: str = "robot") -> int:
    children = spawn_all(settings, host)

    time.sleep(STARTUP_GRACE_S)
    started = [n for n, p in children.items() if p.poll() is None]
    refused = [n for n, p in children.items() if p.poll() is not None]
    report_startup(settings, children, started, refused)

    signal.signal(signal.SIGTERM, request_shutdown)
    signal.signal(signal.SIGINT, request_shutdown)
    try:
        watch(children, started)
    except (ShutdownRequested, KeyboardInterrupt):
        pass
    finally:
        signal.signal(signal.SIGTERM, signal.SIG_DFL)
        signal.signal(signal.SIGINT, signal.SIG_DFL)
        stop_children(children)
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--node", choices=sorted(NODE_TYPES))
    parser.add_argument("--host", default="robot")
    args, rest = parser.parse_known_args()
    if args.node:
        return run_one(args.node, rest)
    return supervise(GraphSettings(), args.host)


if __name__ == "__main__":
    sys.exit(main())

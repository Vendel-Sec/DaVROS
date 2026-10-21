#!/usr/bin/env bash
# The peer, an operator station or another robot: runs the deployment nodes
# that live off the robot.
set -uo pipefail

set +u
for f in /opt/ros/*/setup.bash; do source "$f"; done
set -u

# Inherit the posture the target was provisioned with.
set -a; . /keystore/target.env; set +a
unset ROS_SECURITY_ENCLAVE_OVERRIDE

# rmw_zenoh: no router here, so the peer's sessions dial the robot's.
if [[ "${RMW_IMPLEMENTATION:-}" == "rmw_zenoh_cpp" ]]; then
    [[ -n "${ZENOH_ROUTER_CONFIG_URI:-}" ]] || unset ZENOH_ROUTER_CONFIG_URI
    proto=tcp
    if [[ -n "${ZENOH_SESSION_CONFIG_URI:-}" ]]; then proto=tls; else unset ZENOH_SESSION_CONFIG_URI; fi
    export ZENOH_CONFIG_OVERRIDE="connect/endpoints=[\"${proto}/davros-target:7447\"]"
fi

exec /opt/davros/venv/bin/python -m simulated_target.robot.graph --host peer

#!/usr/bin/env bash
# Leaf B.0.2. Started by entrypoint.sh when TARGET_ROSBRIDGE=true.
set -uo pipefail

# ROS's setup.bash reads AMENT_TRACE_SETUP_FILES without a default, which is an
# error under set -u and kills the script at this line.
set +u
source "/opt/ros/${ROS_DISTRO}/setup.bash"
set -u

# It borrows a real enclave. That is the point: the bridge is inside the trust
# boundary and its WebSocket clients are not authenticated at all.
BRIDGE_ENCLAVE="${1:-/mission_planner}"
export ROS_SECURITY_ENCLAVE_OVERRIDE="${BRIDGE_ENCLAVE}"
if [[ -n "${ZENOH_SESSION_CONFIG_URI:-}" ]]; then
    export ZENOH_SESSION_CONFIG_URI="/keystore/enclaves${BRIDGE_ENCLAVE}/zenoh_session.json5"
fi

cat <<BANNER
------------------------------------------------------------------
 rosbridge_server, UNAUTHENTICATED, bound to 0.0.0.0:9090
   enclave borrowed : ${BRIDGE_ENCLAVE}
   security enable  : ${ROS_SECURITY_ENABLE:-<unset>}
   leaf             : B.0.2
   consequence      : E1 E2 E3, with no host exploit required
------------------------------------------------------------------
BANNER

exec ros2 launch rosbridge_server rosbridge_websocket_launch.xml \
    address:=0.0.0.0 port:=9090

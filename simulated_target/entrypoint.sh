#!/usr/bin/env bash
# Simulated target entrypoint.
set -uo pipefail

: "${ROS_DISTRO:?not set, so the ROS installation cannot be located}"

# ROS's setup.bash reads AMENT_TRACE_SETUP_FILES without a default, which is an
# error under set -u and kills the script at this line.
set +u
source "/opt/ros/${ROS_DISTRO}/setup.bash"
set -u

MODE="${1:-graph}"

echo "=================================================================="
echo " DaVROS, ROS 2 ${ROS_DISTRO}, simulated target"
echo "=================================================================="

# --- the assessor's ssh access ------------------------------------------- #
# Not part of the posture. The keys live in the target-access volume, so a
# recreate for a new posture keeps the host key the assessor already trusts.
install -d -m 0755 /access
install -d -m 0700 /access/host
[[ -f /access/host/ssh_host_ed25519_key ]] \
    || ssh-keygen -q -t ed25519 -N '' -C davros-target -f /access/host/ssh_host_ed25519_key
[[ -f /access/id_ed25519 ]] \
    || ssh-keygen -q -t ed25519 -N '' -C auditor@davros-target -f /access/id_ed25519
# uid 1000 is the account in davros-attacker and in tools such as ROS2probe.
# ssh refuses a private key that anyone but its owner can read.
chown 1000:1000 /access/id_ed25519 && chmod 0600 /access/id_ed25519
install -d -o auditor -g auditor -m 0700 /home/auditor/.ssh
install -o auditor -g auditor -m 0600 /access/id_ed25519.pub /home/auditor/.ssh/authorized_keys
echo "davros-target $(cut -d' ' -f1,2 /access/host/ssh_host_ed25519_key.pub)" > /access/known_hosts
# For clients that mount the volume at /target-access, as davros-attacker does.
cat > /access/ssh_config <<'SSHCONFIG'
Host davros-target
    User auditor
    IdentityFile /target-access/id_ed25519
    UserKnownHostsFile /target-access/known_hosts
    StrictHostKeyChecking yes
    BatchMode yes
SSHCONFIG
mkdir -p /run/sshd
/usr/sbin/sshd || echo "WARNING: sshd did not start, the host is unreachable over ssh" >&2

# --- provision ----------------------------------------------------------- #
/opt/davros/venv/bin/python -m simulated_target.provisioning.cli || {
    echo "FATAL: provisioning failed" >&2
    exit 1
}

# --- the runtime environment for the nodes ------------------ #
# A.0 family
export ROS_SECURITY_ENABLE="${TARGET_SECURITY_ENABLE:-true}"
export ROS_SECURITY_STRATEGY="${TARGET_SECURITY_STRATEGY:-Enforce}"
export ROS_SECURITY_KEYSTORE="${TARGET_KEYSTORE:-/keystore}"
export ROS_DOMAIN_ID="${TARGET_DOMAIN_ID:-42}"
export RMW_IMPLEMENTATION="${TARGET_RMW:-${RMW_IMPLEMENTATION:-rmw_fastrtps_cpp}}"

# A.0.4
if [[ -n "${TARGET_ENCLAVE_OVERRIDE:-}" ]]; then
    export ROS_SECURITY_ENCLAVE_OVERRIDE="${TARGET_ENCLAVE_OVERRIDE}"
else
    unset ROS_SECURITY_ENCLAVE_OVERRIDE
fi

# A.0.5 / A.1.6 / A.1.7 / A.1.8 live in the rmw profile
unset FASTRTPS_DEFAULT_PROFILES_FILE CYCLONEDDS_URI
unset ZENOH_ROUTER_CONFIG_URI ZENOH_SESSION_CONFIG_URI ZENOH_CONFIG_OVERRIDE
if [[ "${TARGET_OMIT_PLUGINS:-false}" != "true" ]]; then
    if [[ "${RMW_IMPLEMENTATION}" == "rmw_zenoh_cpp" ]]; then
        export ZENOH_ROUTER_CONFIG_URI="/keystore/zenohd.json5"
        export ZENOH_SESSION_CONFIG_URI="/keystore/zenoh_session.json5"
    elif [[ "${RMW_IMPLEMENTATION}" == "rmw_cyclonedds_cpp" ]]; then
        export CYCLONEDDS_URI="file:///keystore/cyclonedds.xml"
    else
        export FASTRTPS_DEFAULT_PROFILES_FILE="/keystore/fastdds_profile.xml"
    fi
fi

cat <<POSTURE

------------------------------------------------------------------
 effective runtime environment
   ROS_SECURITY_ENABLE            : ${ROS_SECURITY_ENABLE}
   ROS_SECURITY_STRATEGY          : ${ROS_SECURITY_STRATEGY}
   ROS_SECURITY_KEYSTORE          : ${ROS_SECURITY_KEYSTORE}
   ROS_SECURITY_ENCLAVE_OVERRIDE  : ${ROS_SECURITY_ENCLAVE_OVERRIDE:-<unset>}
   ROS_DOMAIN_ID                  : ${ROS_DOMAIN_ID}
   RMW_IMPLEMENTATION             : ${RMW_IMPLEMENTATION}
   FASTRTPS_DEFAULT_PROFILES_FILE : ${FASTRTPS_DEFAULT_PROFILES_FILE:-<unset>}
   CYCLONEDDS_URI                 : ${CYCLONEDDS_URI:-<unset>}
   ZENOH_ROUTER_CONFIG_URI        : ${ZENOH_ROUTER_CONFIG_URI:-<unset>}
   ZENOH_SESSION_CONFIG_URI       : ${ZENOH_SESSION_CONFIG_URI:-<unset>}
------------------------------------------------------------------

POSTURE

# A.1.4, A.4.1: root owns the artefacts, keys included. The ROS account reads
# them through the group and cannot rewrite its own security configuration.
chown -R root:ros /keystore 2>/dev/null || true

# setpriv reads no profile, so the ROS environment is carried across by hand.
node_env=(
    "PATH=${PATH}"
    "HOME=/home/ros"
    "ROS_DISTRO=${ROS_DISTRO}"
    "ROS_SECURITY_ENABLE=${ROS_SECURITY_ENABLE}"
    "ROS_SECURITY_STRATEGY=${ROS_SECURITY_STRATEGY}"
    "ROS_SECURITY_KEYSTORE=${ROS_SECURITY_KEYSTORE}"
    "ROS_DOMAIN_ID=${ROS_DOMAIN_ID}"
    "RMW_IMPLEMENTATION=${RMW_IMPLEMENTATION}"
    ${ROS_SECURITY_ENCLAVE_OVERRIDE:+"ROS_SECURITY_ENCLAVE_OVERRIDE=${ROS_SECURITY_ENCLAVE_OVERRIDE}"}
    ${FASTRTPS_DEFAULT_PROFILES_FILE:+"FASTRTPS_DEFAULT_PROFILES_FILE=${FASTRTPS_DEFAULT_PROFILES_FILE}"}
    ${CYCLONEDDS_URI:+"CYCLONEDDS_URI=${CYCLONEDDS_URI}"}
    ${ZENOH_ROUTER_CONFIG_URI:+"ZENOH_ROUTER_CONFIG_URI=${ZENOH_ROUTER_CONFIG_URI}"}
    ${ZENOH_SESSION_CONFIG_URI:+"ZENOH_SESSION_CONFIG_URI=${ZENOH_SESSION_CONFIG_URI}"}
    ${AMENT_PREFIX_PATH:+"AMENT_PREFIX_PATH=${AMENT_PREFIX_PATH}"}
    ${LD_LIBRARY_PATH:+"LD_LIBRARY_PATH=${LD_LIBRARY_PATH}"}
    ${PYTHONPATH:+"PYTHONPATH=${PYTHONPATH}"}
)

drop_to_ros=(setpriv --reuid=ros --regid=ros --init-groups env "${node_env[@]}")

case "${MODE}" in
  graph)
    # rmw_zenoh: nodes reach each other through the router, so it starts first.
    if [[ "${RMW_IMPLEMENTATION}" == "rmw_zenoh_cpp" ]]; then
        echo "starting rmw_zenohd as user 'ros'"
        "${drop_to_ros[@]}" ros2 run rmw_zenoh_cpp rmw_zenohd &
        for _ in $(seq 30); do
            ss -ltn | grep -q ':7447 ' && break
            sleep 0.5
        done
        ss -ltn | grep -q ':7447 ' || echo "WARNING: rmw_zenohd is not listening on 7447" >&2
    fi

    # B.0.2: bridge robot process
    if [[ "${TARGET_ROSBRIDGE:-false}" == "true" ]]; then
        echo "starting rosbridge_server as user 'ros' (B.0.2)"
        "${drop_to_ros[@]}" /opt/davros/rosbridge.sh \
            "${TARGET_ROSBRIDGE_ENCLAVE:-/mission_planner}" &
    fi

    echo "starting robot graph as user 'ros'"
    exec "${drop_to_ros[@]}" /opt/davros/venv/bin/python -m simulated_target.robot.graph
    ;;
  provision)
    echo "provision-only mode, keystore is ready"
    exec sleep infinity
    ;;
  shell)
    exec bash
    ;;
  *)
    exec "$@"
    ;;
esac

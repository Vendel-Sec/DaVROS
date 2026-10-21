# Borrow /motion_controller's identity from a stolen keystore. Source it in
# davros-attacker:
#
#   source demo/add_enclave_env.sh [keystore]
#
# keystore  defaults to the first */keystore under demo/evidence/, wherever
#           binwalk or debugfs unpacked it
_evidence="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)/evidence"
_ks="${1:-$(find "$_evidence" -type d -path '*/keystore/enclaves' 2>/dev/null | head -n 1)}"
_ks="${_ks%/enclaves}"
if [ -z "$_ks" ] || [ ! -d "$_ks/enclaves/motion_controller" ]; then
    echo "no keystore with a motion_controller enclave under $_evidence, pass its path" >&2
    unset _ks _evidence
    return 1
fi
# Kept so remove_enclave_env.sh can put the attacker's own domain back.
export DAVROS_DEMO_PREVIOUS_DOMAIN="${ROS_DOMAIN_ID-}"
export ROS_SECURITY_KEYSTORE="$(cd "$_ks" && pwd)"
export ROS_SECURITY_ENABLE=true
export ROS_SECURITY_STRATEGY=Enforce
export ROS_SECURITY_ENCLAVE_OVERRIDE=/motion_controller
# The keystore records the domain it was provisioned for.
export ROS_DOMAIN_ID="$(sed -n 's/^ROS_DOMAIN_ID=//p' "$_ks/target.env" 2>/dev/null)"
export ROS_DOMAIN_ID="${ROS_DOMAIN_ID:-42}"
echo "enclave /motion_controller from $ROS_SECURITY_KEYSTORE, domain $ROS_DOMAIN_ID"
unset _ks _evidence

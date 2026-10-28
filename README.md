# DaVROS

**Damn Vulnerable ROS**: a deliberately misconfigurable ROS 2 robot, the peer it talks to, and an attacker on the segment between them. It is for learning the security of ROS 2: DDS-Security misconfiguration (branch A) and the Ubuntu host underneath (branch B), as laid out in [ros2_attack_tree.md](ros2_attack_tree.md).

DaVROS is self-contained. Tools such as ROS2probe can use it as a practice target, but it depends on none of them.

> [!WARNING]
> DaVROS is vulnerable on purpose. Run it on a machine and network you control, never alongside a real robot's domain, and keep it off shared networks. The presets disable DDS-Security, weaken file modes and, with `TARGET_ROSBRIDGE=true`, open an unauthenticated rosbridge WebSocket. The compose file publishes that WebSocket on `127.0.0.1:9090` only. Use the leaves against a real robot only with written authorization.

## AI disclosure

This project was developed with the assistance of AI tools (Anthropic Claude) and was reviewed and modified by the maintainers.

## 1. Start the lab

```sh
docker compose up -d --build
docker exec -it davros-attacker bash      # the attacker
```

This starts `davros-target`, the robot, and `davros-peer`, its peer, on the `davrosnet` bridge, with `davros-attacker` beside them. The peer stands for whatever the robot talks to off-box: an operator station, or another robot in the fleet. That bridge is the attacker's segment: on the network, no credentials, no account on the robot. The ssh key at `/target-access` is the assessor's access for host checks ([section 3](#3-validate-a-leaf-by-hand)), not part of that position. [docs/07-davros-topology.md](docs/07-davros-topology.md) diagrams it.

## 2. Make the target vulnerable

The target's DDS-Security layer is hardened by default. Switch posture with a preset and recreate it:

```sh
cp simulated_target/posture/presets/all-open.env simulated_target/posture/preset.env
docker compose up -d --force-recreate --wait target peer

rm simulated_target/posture/preset.env     # back to hardened
```

The presets live in [simulated_target/posture/presets/](simulated_target/posture/presets/), each isolating one leaf or one group of leaves, mostly in branch A (`exposed-rosbridge` is B.0.2, `tls-no-client-auth` needs Zenoh), and `all-open` sets every knob to its vulnerable value. Recreate `peer` with `target`: it reads the keystore only when it starts, and the target reprovisions it.

Some presets also move the robot off domain 42: `all-open` and `never-configured` put it on 0. `davros-attacker` does not follow, because finding the domain is part of A.0.6. Read it from `/target-keystore/target.env`, or scan for it, then `export ROS_DOMAIN_ID=0` in `davros-attacker`.

### From a browser: the configurator

```sh
./configurator.py                  # then open http://127.0.0.1:8765
./configurator.py --port 9000      # another port
```

It runs on the host with the system Python 3 and nothing to install, from any directory. It shows every knob of `target.env` as a switch, radio buttons or a text field, grouped by branch with the leaves each one decides.

- **Start from a preset**, or from the hardened baseline, then change any knob.
- **Save** writes `simulated_target/posture/preset.env` with only the knobs that differ from the baseline. Saving the baseline unchanged removes `preset.env`.
- **Save and recreate target** also runs `docker compose up -d --force-recreate --wait target peer`, so the target and the peer come back under the new posture. It needs `docker` on the host's `PATH`. Errors also print in the configurator's terminal.

It listens on `127.0.0.1` and refuses any other `Host` header, because it writes files and drives docker. To reach it through a forwarded name, add `--allow-host <name>`. `--host 0.0.0.0` exposes it to the network; don't.

### Fast DDS, Cyclone DDS or Zenoh

```sh
docker compose up -d --build --force-recreate target peer                                 # Fast DDS (default)
TARGET_RMW=rmw_cyclonedds_cpp docker compose up -d --build --force-recreate target peer   # Cyclone DDS
TARGET_RMW=rmw_zenoh_cpp docker compose up -d --build --force-recreate target peer        # Zenoh
```

The target's ROS 2 release is a build argument, default `jazzy`:

```sh
TARGET_ROS_DISTRO=humble docker compose build target
```

The attacker is set to `jazzy`. The cross-distro runs are documented: [docs/06-cross-distro-targets.md](docs/06-cross-distro-targets.md).

## 3. Validate a leaf by hand

Every leaf in [docs/](docs/) documents its manual validation. Those commands read eight variables and assume bash, since zsh does not split `$RUN` into words. For the lab, set them in `davros-attacker`:

```sh
export KEYSTORE=/target-keystore
export ENVFILE=$KEYSTORE/target.env XMLPROFILE=$KEYSTORE/fastdds_profile.xml
export DOMAIN=$(sed -n 's/^ROS_DOMAIN_ID=//p' $ENVFILE) IFACE=eth0 TARGET=davros-target ROSUSER=ros
export RUN="ssh -F /target-access/ssh_config davros-target sudo -n"   # root on the robot, over ssh
```

For a real robot, point them at copies of its files:

```sh
export KEYSTORE=/home/attacker/acme/keystore-copy
export ENVFILE=/home/attacker/acme/ros-security.env
export XMLPROFILE=/home/attacker/acme/fastdds_profile.xml       # or cyclonedds.xml
export DOMAIN=17 IFACE=enp3s0 TARGET=10.20.0.11 ROSUSER=ros
export RUN="ssh pentest@10.20.0.11"

stat -c '%a %U' $KEYSTORE/enclaves/*/key.pem                 # A.1.4
$RUN ls -l /dev/shm                                          # B.2.6
```

`$RUN` reaches the lab's robot the way it reaches a real one, over ssh. `davros-target` runs an `sshd` for `auditor`, the account a client hands whoever audits the robot: key only, no root login, passwordless sudo. It is how the host is inspected, not part of the posture, so it stays hardened under every preset and B.0.1 passes against it. Its key, the target's host key and an `ssh_config` are in the `target-access` volume, mounted read-only at `/target-access` in `davros-attacker`, and they survive a recreate. Drop `sudo -n` from `$RUN` for what `auditor` itself can do.

```sh
# Zenoh target only
export ZSESSION=$KEYSTORE/zenoh_session.json5
export ZROUTER=$KEYSTORE/zenohd.json5
zq() { uv run --no-project --with json5 python -c 'import json, sys, json5
value = json5.load(open(sys.argv[1]))
for key in filter(None, sys.argv[2].split(".")):
    value = value.get(key) if isinstance(value, dict) else None
print(json.dumps(value, indent=1))' "$1" "${2:-}"; }

zq $ZSESSION transport.link.tls.enable_mtls                  # A.1.1
```

## 4. Demos

[demo/](demo/README.md) walks an offline attack. Export the target's filesystem with `demo/export-target-ext4.sh` from the host and unpack it into `demo/evidence/` with `binwalk -e` or `debugfs`. Then, in `davros-attacker`, `source demo/add_enclave_env.sh` to borrow `/motion_controller`'s enclave and run `python3 demo/echo_cmd_vel.py` to read `/cmd_vel`. `source demo/remove_enclave_env.sh` drops the identity again.

## Layout

```
docker-compose.yml     davros-attacker, davros-target and davros-peer on the davrosnet bridge
configurator.py        the posture configurator, a web UI over simulated_target/posture/
attacker/              the davros-attacker image
simulated_target/      the robot and peer image, provisioning, posture presets and the configurator's page
ros2_attack_tree.md    the attack tree's index
docs/                  conventions, one page per leaf group with manual validation per leaf, topology
demo/                  an offline keystore-theft walkthrough
```

## License

Apache-2.0, see [LICENSE](LICENSE). The images install third-party software at build time under its own licenses, listed in [NOTICE](NOTICE).

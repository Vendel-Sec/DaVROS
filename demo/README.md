# Demo: stealing an enclave offline

DDS-Security trusts whoever holds an enclave's private key. This demo shows what that means once the key leaves the robot. You copy the robot's filesystem, take `/motion_controller`'s enclave from it, and join the robot's graph as that node. You then read every velocity command the peer sends. The target runs its **hardened baseline** throughout: security enabled, `Enforce`, encryption on every topic, access control on, a CRL configured. The only weakness used is one the documented SROS2 setup always has: enclave keys are stored in the clear.

| | |
|---|---|
| Attacker | T4 for the copy (a backup, a disk pulled from a parked robot, an RMA unit, a firmware image), then T2 on the network: one valid credential |
| Leaves | A.1.5 key not encrypted at rest, which the baseline keeps by design. A.1.6 and A.4.5, revocation and rotation, help only once someone notices the theft |
| Consequence | E3 here (`/cmd_vel` read in the clear). The same identity may publish `/odom` and `/robot_state`, which is E2 |
| Time | About five minutes, most of it the export |

## Before you start

Start the lab from the repository root (see the [top-level README](../README.md)):

```sh
docker compose up -d --build
```

On the host you also need `e2fsprogs` and `fakeroot`, and optionally `binwalk`:

```sh
sudo apt-get install e2fsprogs fakeroot
```

Everything the demo produces goes to `demo/evidence/`, which git ignores. The scripts locate it from their own path, so they work from any directory.

## 1. Copy the robot's filesystem (host)

```sh
demo/export-target-ext4.sh                  # demo/evidence/davros-target.ext4
```

This stands in for the attacker's copy. It is the container's filesystem plus the `/keystore` volume, packed as an ext4 image with owners and modes as on the target, so it unpacks like a disk image or a firmware dump. `davros-target` is the default container; pass another name as the first argument, and an output path as the second.

## 2. Unpack it (host)

With binwalk, as you would a firmware image:

```sh
(cd demo/evidence && binwalk -e davros-target.ext4)
```

Or with `debugfs` from e2fsprogs, which needs nothing else and takes only the keystore:

```sh
mkdir -p demo/evidence/davros-target.ext4.debugfs
/usr/sbin/debugfs -R "rdump /keystore demo/evidence/davros-target.ext4.debugfs" \
    demo/evidence/davros-target.ext4
```

`debugfs` warns that it cannot change ownership. That is expected without root; the files are still readable.

## 3. Look at what you took (davros-attacker)

```sh
docker exec -it -w /workspace davros-attacker bash
K=$(find demo/evidence -type d -path '*/keystore/enclaves' | head -n 1)
ls $K
```

Every node's enclave is there: `diagnostics`, `listener`, `mission_planner`, `motion_controller`, `odom_publisher`, `scan_publisher`, `talker`. Pick one:

```sh
E=$K/motion_controller
head -1 $E/key.pem                                       # A.1.5
openssl x509 -in $E/cert.pem -noout -subject -issuer -enddate
```

```
-----BEGIN EC PRIVATE KEY-----
subject=CN = /motion_controller
issuer=CN = sros2CA
notAfter=Oct 21 16:03:35 2027 GMT
```

The key has no `Proc-Type: 4,ENCRYPTED` header, so it is in the clear. That is what `ros2 security create_enclave` writes, and sros2 has no way to hand the RMW a passphrase. The certificate is valid for a year. The enclave does carry an `identity_crl.pem`, but a CRL revokes only keys someone knows are gone, and an offline copy leaves no trace on the robot.

`permissions.xml` says what the identity may do:

```sh
grep -oE '<(publish|subscribe)>|<topic>rt/[^<]+' $E/permissions.xml | sed 's#<topic>##'
```

For `/motion_controller` that is subscribing to `rt/cmd_vel`, `rt/clock` and `rt/parameter_events`, and publishing `rt/odom`, `rt/robot_state`, `rt/rosout` and `rt/parameter_events`.

## 4. Join the graph as that node (davros-attacker)

```sh
source demo/add_enclave_env.sh              # finds the keystore under demo/evidence/
python3 demo/echo_cmd_vel.py                # Ctrl-C to stop
```

```
enclave /motion_controller from /workspace/demo/evidence/davros-target.ext4.debugfs/keystore, domain 42
geometry_msgs.msg.Twist(linear=geometry_msgs.msg.Vector3(x=0.0, y=0.0, z=0.0), angular=...)
```

`add_enclave_env.sh` sets `ROS_SECURITY_*` to the stolen keystore with `Enforce` and `ROS_SECURITY_ENCLAVE_OVERRIDE=/motion_controller`. It reads the domain from the stolen `target.env`, so it follows whatever posture the target was in. To use another keystore, pass its path: `source demo/add_enclave_env.sh demo/evidence/<dir>/keystore`.

`echo_cmd_vel.py` is a node named `/cmd_vel_eavesdropper` that subscribes to `/cmd_vel` and prints every message. It turns off its parameter and type-description services because the stolen permissions do not grant them, and `Enforce` would otherwise refuse to create the node.

Every `Twist` the peer sends now arrives decrypted. On the wire nothing distinguishes the attacker from the real `/motion_controller`: same certificate, same permissions, same encryption keys.

## 5. Drop the identity (davros-attacker)

```sh
source demo/remove_enclave_env.sh
```

This unsets the security variables and puts back the domain the shell had before, so later commands run unauthenticated again, as `davros-attacker` normally does.

## Why DDS-Security does not stop this

DDS-Security authenticates keys, not machines. The handshake proves that the peer holds a private key the CA signed, and access control then grants whatever the matching `permissions.p7s` allows. Nothing binds the key to the host it was issued for. Encryption on every topic does not help either, because the session keys are negotiated with the stolen identity like any other.

File modes (A.1.4) and keystore ownership (A.4.2) keep other local accounts out (T3). They do nothing once the disk or a backup leaves the building, because the key is in the clear on that disk.

## Try it under a weaker posture

`fleet-identity` is the same theft on a badly provisioned fleet:

```sh
cp simulated_target/posture/presets/fleet-identity.env simulated_target/posture/preset.env
docker compose up -d --force-recreate --wait target peer
```

Then export and unpack again (steps 1 and 2). Three things change in the stolen keystore:

- Every enclave carries the same certificate, `CN = /robot` (A.1.3), so one robot's key works on every robot in the fleet (E5).
- `keystore/private/` holds `ca.key.pem`, `identity_ca.key.pem` and `permissions_ca.key.pem` (A.4.3). With those you no longer need to borrow an identity: you can sign your own certificate and your own `permissions.p7s` granting anything.
- The keys are `0644` (A.1.4), so any account in the `ros` group could have copied them on the robot itself, with no disk image needed. The keystore directories stay `0750`; under `all-open` (`TARGET_KEYSTORE_MODE=0777`) that widens to any local account.

Remove `preset.env` and recreate `target` and `peer` to return to the baseline.

## Remediation

- **Keep the key off the disk in the clear.** Use a TPM or PKCS#11 token for enclave keys (A.1.5). A passphrase alone does not work: sros2 cannot pass it to the RMW, so every node fails to start.
- **Make theft survivable.** Keep certificate lifetimes short (A.1.9), keep the CRL current (A.1.6), and write and rehearse a rotation runbook (A.4.5), so that a key known to be stolen stops working quickly.
- **Never ship the CA.** Remove `keystore/private/` before the keystore reaches a robot (A.4.3).
- **One identity per robot and per node** (A.1.3), so a stolen key is limited to that node's permissions on one robot.
- **Protect the copies.** Backups, images and returned units carry the keystore. Encrypt them at rest and wipe returned hardware.

See [a1-authentication.md](../docs/02-branch-a/a1-authentication.md) and [a4-artefact-delivery.md](../docs/02-branch-a/a4-artefact-delivery.md) for each leaf's manual check.

## Troubleshooting

- **No messages, and no error.** The stolen keystore is stale. Every recreate of `target` reprovisions it with a new CA, and keys taken before it no longer authenticate. Delete `demo/evidence/` and repeat steps 1 and 2 after any recreate.
- **No messages after a posture change.** Check the domain: `echo $ROS_DOMAIN_ID` must match `ROS_DOMAIN_ID` in the stolen `target.env`, which is what `add_enclave_env.sh` uses. Re-source it after a fresh export.
- **`no keystore with a motion_controller enclave`.** Nothing is unpacked under `demo/evidence/`, or the unpacker put it elsewhere. Pass the path explicitly.
- **Several exports.** `add_enclave_env.sh` takes the first keystore it finds. Remove older ones or pass a path.
- **`export-target-ext4.sh` stops with `no container named davros-target`.** Start the lab first.

## Clean up

```sh
rm -rf demo/evidence                        # on the host, about 1.2 GB
```

## Files

| File | Runs on | Does |
|---|---|---|
| [export-target-ext4.sh](export-target-ext4.sh) | host | Packs a container's filesystem and volumes into `demo/evidence/<container>.ext4` |
| [add_enclave_env.sh](add_enclave_env.sh) | davros-attacker, sourced | Points `ROS_SECURITY_*` at the stolen keystore as `/motion_controller` |
| [echo_cmd_vel.py](echo_cmd_vel.py) | davros-attacker | Subscribes to `/cmd_vel` as `/cmd_vel_eavesdropper` and prints each message |
| [remove_enclave_env.sh](remove_enclave_env.sh) | davros-attacker, sourced | Unsets those variables again |

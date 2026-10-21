## B.2 Converting host access into ROS compromise (T3 to T4)

Commands below use `$KEYSTORE`, `$ENVFILE`, `$RUN` and the rest; [the README](../../README.md) sets them.

The leaves are drawn in [the branch B tree](../03-branch-b-unsecured-ubuntu-host.md). The lab's target is a container, not a robot host: it has no systemd, sshd, ufw, timesyncd, auditd or rsyslog. A leaf whose check needs one of them is undecidable in the lab, and a `not found` there is not a pass.

### B.2.1 Enclave keys not readable

`Cons E1 E2 E3 E5` · `T T3` · `P P3` · `X X3`

**Action.** Read `enclaves/<node>/key.pem` and `cert.pem`

**Why the DDS-Security layer does not stop it.** The attacker is now a cryptographically legitimate participant. If A.1.3 also holds, a shared fleet identity, this credential works on every robot.

```sh
$RUN id -un
$RUN sh -c 'cat /keystore/enclaves/*/key.pem' > /dev/null; echo $?
```

Exit 0 is the finding: the account holds a cryptographically legitimate participant identity, and if A.1.3 also holds it works on every robot in the fleet. Exit 1 is only meaningful once the first command confirms you are not root. Modes raise the bar but never close this leaf: they stop another local account (T3), not root (T4), and only a key in a TPM or PKCS#11 token is out of root's reach.

In the lab `$RUN` is root. For the T3 view, run it as the ROS account: `docker exec -u ros davros-target sh -c 'cat /keystore/enclaves/*/key.pem' > /dev/null; echo $?`.

### B.2.2 Security environment cannot be flipped

`Cons E1 E2 E3 E4` · `T T4` · `P P3` · `X X3`

**Action.** Edit the systemd unit, `.bashrc` or launch file to remove `ROS_SECURITY_ENABLE`, or set `ROS_SECURITY_STRATEGY` to anything but `Enforce`

**Why the DDS-Security layer does not stop it.** Permissive is the default, so the robot restarts with security silently off and no error in the logs. This is the quietest available persistence.

```sh
$RUN systemctl cat <unit>
$RUN grep -rlIE '^\s*(export\s+)?ROS_SECURITY_[A-Z_]+=' /etc /opt /home 2>/dev/null
$RUN stat -Lc '%a %U %G %n' <each hit>
```

More than one file setting `ROS_SECURITY_*` is itself the finding: the effective value is whichever is read last, and a `.bashrc` or launch file that `$ROSUSER` can write beats a hardened unit. Any writable one is the quietest persistence available, because `Permissive` is the default and the robot restarts with security off and nothing in the logs.

**Zenoh.** The variables to protect are `ZENOH_ROUTER_CONFIG_URI`, `ZENOH_SESSION_CONFIG_URI` and above all `ZENOH_CONFIG_OVERRIDE` (A.0.4). An account that can set any one of them in the unit turns the transport's security off.

### B.2.3 Policy documents cannot be replaced

`Cons E1 E2 E3` · `T T4` · `P P3` · `X X2`

**Action.** Replace `governance.p7s` or `permissions.p7s`, which needs the Permissions CA key, see A.3.15 and A.4.3, or the signature check fails

**Why the DDS-Security layer does not stop it.** If the CA key is on the robot, the signature check is not a control. If it is not, this step fails, which is exactly why A.4.3 matters.

```sh
$RUN sh -c "stat -Lc '%a %U %G %n' /keystore/enclaves/governance.p7s /keystore/enclaves/*/permissions.p7s"
$RUN ls -l /keystore/private
```

Writable documents alone are not sufficient — replacing them needs the Permissions CA key so the signature still verifies. Writable documents *and* a key in `private/` is the finding, and that pairing is exactly why A.4.3 matters. Follow symlinks: sros2 links each enclave's `governance.p7s` at the keystore-wide document, and a symlink's own mode always reads `0777`.

### B.2.4 Safety parameters not reachable

`Cons E1 E2 E4` · `T T3` · `P P3` · `X X3`

**Action.** Attack the node process directly: `LD_PRELOAD` a shim into the RMW, `ptrace` the running node, replace the Python entry point, or `ros2 param set` on safety limits such as max velocity, geofence or watchdog timeout

**Why the DDS-Security layer does not stop it.** All of this happens **inside** the trust boundary, after decryption. DDS-Security protects the wire, not the process.

```sh
ROS_DOMAIN_ID=$DOMAIN ros2 param list /motion_controller
ROS_DOMAIN_ID=$DOMAIN ros2 param get /motion_controller max_velocity
```

Reaching the parameter service at all is the finding — a reachable safety limit is a settable one. **Read only.** Never run `ros2 param set` against a machine that can move: a changed velocity limit, geofence or watchdog timeout is not a test result worth having. The `LD_PRELOAD` and `ptrace` halves of this leaf are host-side: `LD_PRELOAD` through a writable unit (B.1.2) or workspace (B.1.3), `ptrace` as the node's own account (B.1.0) or root.

**Zenoh.** The parameter service is reached through the router. Before any session, open TCP to the router and try TLS with no client certificate, as in A.1.1. A router that answers with a certificate alert has refused the T1 attacker, and the leaf passes. A router speaking plaintext gives a session, and the parameters can be read. By hand, from the attacker's machine, against a plaintext router:

```sh
( export ROS_DOMAIN_ID=$DOMAIN RMW_IMPLEMENTATION=rmw_zenoh_cpp \
         ZENOH_CONFIG_OVERRIDE="mode=\"client\";connect/endpoints=[\"tcp/$TARGET:7447\"]"
  ros2 param get /motion_controller max_velocity
  ros2 daemon stop )
```

A value back is the finding. Stop the daemon afterwards, or it keeps the Zenoh environment and later DDS commands see nothing. Against a router with mTLS, the connection is refused, which is the control holding for T1. Asking with a held certificate is the T2 version of the leaf.

### B.2.5 Authenticated time source

`Cons E4` · `T T4` · `P P3` · `X X3`

**Action.** Point the host at an attacker-controlled or spoofed NTP server

**Why the DDS-Security layer does not stop it.** Certificate `notAfter` and permissions `<validity>` are evaluated against the local clock. A forward jump causes mass authentication failure and fleet-wide E4, a backward jump makes expired credentials acceptable. Stock `systemd-timesyncd` authenticates neither the server nor the response.

```sh
$RUN timedatectl show
$RUN cat /etc/systemd/timesyncd.conf
```

`NTP=` pointing at a plain NTP server is the finding: stock `systemd-timesyncd` authenticates neither the server nor the response. This is what makes A.1.9 and A.3.12 unenforceable — expiry evaluated against a clock the attacker sets is not a bound.

### B.2.6 Shared memory not world-accessible

`Cons E2 E4` · `T T3` · `P P3` · `X X3`

**Action.** Read or write the Fast DDS shared-memory segments in `/dev/shm` used for intra-host transport

**Cyclone DDS.** Cyclone has no SHM transport of its own. On 0.10.x, the release Jazzy ships, it uses shared memory only through Iceoryx, when `<SharedMemory><Enable>` is `true`, and the RouDi daemon then owns the segments: `iceoryx_mgmt` and one payload segment per configured group, named after it. With shared memory off, which is the default, there is nothing in `/dev/shm` to find and the leaf does not apply.

**Why the DDS-Security layer does not stop it.** The transport creates its segments with nothing beyond the default umask restricting them, so any local account can open them and tamper with or deny intra-host traffic. Where `data_protection_kind` is `NONE`, see A.2.6, the payloads are also readable directly.

```sh
$RUN ls -l /dev/shm
```

`fastrtps_*` segments readable or writable beyond their owner is the finding: any local account opens them and tampers with or denies intra-host traffic, and where `data_protection_kind` is `NONE` reads the payloads directly. The transport applies nothing but the umask, so `UMask=0007` on the ROS service is the fix.

On Cyclone DDS, `iceoryx_*` segments readable or writable beyond their owner are the same finding. The fix is RouDi's group configuration, plus the umask of the account RouDi runs as. Matching `iceoryx` and `iox` in segment names misses a payload segment named after a group, so read the full listing.

**Example**, the lab in its `all-open` posture:

```
-rw-r--r-- 1 ros ros 549408 fastrtps_1d2f6e27d9865334
-rw-r--r-- 1 ros ros      0 fastrtps_1d2f6e27d9865334_el
```

**Zenoh.** Shared memory is off in the rmw_zenoh defaults. `generate_configs` turns it on (`transport.shared_memory.enabled: true`), and the segments appear as `/dev/shm/<id>.zenoh`:

```sh
zq $ZSESSION transport.shared_memory.enabled
$RUN sh -c 'ls -l /dev/shm/*.zenoh'
```

The same finding applies to `.zenoh` segments readable or writable beyond their owner. The lab observed them at `0600`.

### B.2.7 Auditing and remote logging

`Cons E5` · `T T3` · `P P3` · `X X3`

**Action.** No `auditd`, no remote syslog, no host IDS, no DDS-level anomaly detection

**Why the DDS-Security layer does not stop it.** Every step above is invisible, so dwell time is unbounded.

```sh
$RUN systemctl is-active auditd
$RUN grep -rhE '^\*\.\*\s+@' /etc/rsyslog.conf /etc/rsyslog.d/ 2>/dev/null
```

`auditd` inactive is the finding, and no remote target in the rsyslog configuration is the other half: logs that stay on the robot are logs the attacker edits. Every step above is invisible without both, so dwell time is unbounded.

**Example**, the lab in its `all-open` posture:

```
OCI runtime exec failed: ... exec: "systemctl": executable file not found in $PATH
```

**Mitigations** 
- Root-own the keystore, `0750` on enclave directories and `0640` on files, group-owned by the node's account: read, never write. 
- Modes raise the bar but do not close B.2.1, since branch B assumes root. Only a key in a TPM or PKCS#11 token is out of root's reach. 
- Root-own the unit and its `EnvironmentFile`, and fail the unit at `ExecStartPre` unless `Enforce` is set. 
- Set `kernel.yama.ptrace_scope=2`, run each node under its own account, and verify binaries at boot with dm-verity or IMA. 
- Use authenticated time via NTS. 
- Set `UMask=0007` on the ROS service so the Fast DDS segments are group-only. On Cyclone DDS, leave shared memory off unless it is needed, and restrict RouDi's segments to one group. 
- Run `auditd` with remote log shipping, and alert on any unexpected DDS participant joining the domain.

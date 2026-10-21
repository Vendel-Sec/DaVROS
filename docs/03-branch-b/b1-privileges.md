## B.1 Holding the privileges that own the DDS credentials (T3)

Commands below use `$KEYSTORE`, `$ENVFILE`, `$RUN` and the rest; [the README](../../README.md) sets them.

The leaves are drawn in [the branch B tree](../03-branch-b-unsecured-ubuntu-host.md). The lab's target is a container, not a robot host: it has no systemd, sshd, ufw, timesyncd, auditd or rsyslog. A leaf whose check needs one of them is undecidable in the lab, and a `not found` there is not a pass.

### B.1.0 ROS does not run as a login account

`Cons (enabler)` · `T T3` · `P P3` · `X X3`

**Weakness.** **No escalation required.** The ROS launch process runs as the same account the attacker already holds, the usual single `ubuntu` or `ros` user owning SSH access, the colcon workspace and the systemd unit alike

**Path to effect.** The B.1 conjunct is satisfied at zero cost. The attacker already has read access to the keystore, so B.2.1 follows immediately. This leaf exists so that the `[SAND]` at B stays semantically honest.

```sh
$RUN ps -eo user:32,args --no-headers | grep -i ros
$RUN getent passwd <that user>
```

A login shell — `/bin/bash`, `/bin/sh`, `/bin/zsh` — on the account that runs ROS is the finding, and it is the usual single `ubuntu` or `ros` user owning SSH, the workspace and the unit alike. This check decides which account every one below is about.

**Example**, the lab in its `all-open` posture:

```
ros    /opt/davros/venv/bin/python -m simulated_target.robot.graph
ros:x:1500:1500::/home/ros:/bin/bash
```

### B.1.1 No path from the ROS account to root

`Cons (enabler)` · `T T3` · `P P3` · `X X3`

**Weakness.** ROS user in `sudo` with `NOPASSWD`, or in the `docker` group

**Path to effect.** `docker run -v /:/host` gives trivial root. Ubuntu cloud and preinstalled images give the first account `NOPASSWD` sudo through `/etc/sudoers.d/90-cloud-init-users`.

```sh
$RUN id -nG $ROSUSER
$RUN sudo -n -l -U $ROSUSER
```

`docker` in the group list is root: `docker run -v /:/host` and the host filesystem is mounted. `sudo` with `NOPASSWD` is root directly, and Ubuntu cloud images grant the first account exactly that through `/etc/sudoers.d/90-cloud-init-users`. `sudo -l -U` needs root itself; without it, run `sudo -n -l` while holding the account.

**Example**, the lab in its `all-open` posture:

```
ros
```

### B.1.2 Unit and environment file not writable

`Cons (enabler)` · `T T3` · `P P2` · `X X3`

**Weakness.** The systemd unit that launches ROS, or its `EnvironmentFile`, writable by the ROS user

**Path to effect.** Attacker edits `Environment=` to inject `LD_PRELOAD`, or to unset the security variables. Effective at next boot, and it looks like normal configuration. Bridges directly to B.2.2.

```sh
$RUN systemctl cat <unit>
$RUN stat -Lc '%a %U %G %n' <the unit file and every EnvironmentFile it names>
```

Writable by `$ROSUSER` is the finding. Follow the `EnvironmentFile=` lines: the unit is often root-owned while the environment file beside it is not, and that file is where `Environment=` injects `LD_PRELOAD` or drops the security variables. Effective at next boot, and it looks like ordinary configuration.

### B.1.3 Workspace not writable

`Cons (enabler)` · `T T3` · `P P3` · `X X3`

**Weakness.** Workspace `install/` and `setup.bash` writable by a non-privileged user

**Path to effect.** Code execution as the ROS user at next launch, without touching root. **Sufficient on its own**, since the ROS user already holds the DDS credentials.

```sh
$RUN stat -Lc '%a %U %G' /opt/ros2_ws/install/setup.bash
$RUN find /opt/ros2_ws -perm -002 -print
```

A world-writable workspace, or `setup.bash` writable by an unprivileged account, is code execution as `$ROSUSER` at next launch. Sufficient on its own: that account already holds the DDS credentials, so no root is needed.

In the lab, `/opt/ros2_ws` is owned by `ros` and `install/` is empty, so the `stat` reports no such file and the `find` prints nothing. Neither is a pass on a real robot, where the workspace is populated.

### B.1.4 Running kernel matches installed

`Cons (enabler)` · `T T3` · `P P2` · `X X2`

**Weakness.** Kernel not patched, which follows from B.0.3

**Path to effect.** Local privilege escalation to root.

```sh
$RUN uname -r
$RUN dpkg -l 'linux-image-*'
```

A running kernel older than the newest installed one is a pending reboot, and a kernel behind the archive is B.0.3 arriving as local privilege escalation.

### B.1.5 No unexpected SUID or capabilities

`Cons (enabler)` · `T T3` · `P P1` · `X X2`

**Weakness.** Vendor driver binaries shipped SUID or with `cap_sys_admin`

**Path to effect.** Root via the robot's own hardware stack.

```sh
$RUN find / -xdev -perm -4000 -type f 2>/dev/null
$RUN getcap -r / 2>/dev/null
```

Vendor driver binaries that are SUID root, or carry `cap_sys_admin`, are the finding: root by way of the robot's own hardware stack. Distribution SUID binaries are expected; the question is what the vendor added. `getcap: command not found` is undecided, not a clean result.

**Mitigations** 
- Run ROS as a dedicated unprivileged user, not in `docker` or `sudo`, with the workspace and unit files root-owned and read-only. 
- Mount the vendor partition `nosuid`, and give hardware access through a `udev` device group rather than setuid.

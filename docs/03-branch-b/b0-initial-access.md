## B.0 Initial access (T1 to T4)

Commands below use `$KEYSTORE`, `$ENVFILE`, `$RUN` and the rest; [the README](../../README.md) sets them.

The leaves are drawn in [the branch B tree](../03-branch-b-unsecured-ubuntu-host.md). The lab's target is a container, not a robot host: it has no systemd, sshd, ufw, timesyncd, auditd or rsyslog. A leaf whose check needs one of them is undecidable in the lab, and a `not found` there is not a pass.

### B.0.1 SSH refuses passwords and root

`Cons (enabler)` · `T T1` · `P P3` · `X X3`

**Weakness.** `PasswordAuthentication yes`, `PermitRootLogin yes`, a vendor default account, or one `authorized_keys` in the fleet image

**Path to effect.** Credential spray, or one leaked key, gives a shell on every robot. `PasswordAuthentication` is `yes` on a stock Ubuntu server.

```sh
$RUN cat /etc/ssh/sshd_config
$RUN grep -r '' /etc/ssh/sshd_config.d/
```

`PasswordAuthentication yes` — the stock Ubuntu server value — or `PermitRootLogin yes` is the finding. Read the `Include` files too: the effective value is the *first* occurrence across all of them, so a hardened main file can be overridden by a drop-in. `sshd -T` gives the effective config directly but needs root.

### B.0.2 No unauthenticated service exposed

`Cons E1 E2 E3` · `T T1` · `P P3` · `X X3`

**Weakness.** `rosbridge_server`, a web teleop UI, a Foxglove bridge, VNC, MQTT or the Docker API bound to `0.0.0.0` with no auth

**Path to effect.** `rosbridge` in particular is a direct ROS write path that bypasses DDS-Security entirely. `rosbridge_server` binds `0.0.0.0` with no authentication in its own default launch file.

```sh
for p in 9090 8765 8080 5900 1883 2375; do
    timeout 2 bash -c "</dev/tcp/$TARGET/$p" 2>/dev/null && echo "$p open"
done
```

Any of these reachable from the attacker's segment is the finding. 5900, 1883 and 2375 have no business on a robot segment at all; 9090, 8765 and 8080 are findings unless something authenticates in front of them.

The rosbridge half is only partial without a WebSocket client:

```sh
curl -i -N -H 'Connection: Upgrade' -H 'Upgrade: websocket' \
     -H 'Sec-WebSocket-Version: 13' \
     -H "Sec-WebSocket-Key: $(head -c16 /dev/urandom | base64)" \
     http://$TARGET:9090/
```

`101` proves an anonymous upgrade. It does not prove the bridge answers a service call, which is the actual E1 claim — for that, a WebSocket client and a `call_service` frame to `/rosapi/topics`. `davros-attacker` ships `websocat` for this. Transport security is not authentication: a bridge behind TLS that accepts anonymous clients is still the finding.

### B.0.3 Patched and auto-updating

`Cons (enabler)` · `T T1` · `P P2` · `X X2`

**Weakness.** `unattended-upgrades` disabled, a release past EOL without ESM, no patch SLA

**Path to effect.** Known-CVE exploitation of any exposed service or of the kernel.

```sh
$RUN lsb_release -a
$RUN cat /etc/apt/apt.conf.d/20auto-upgrades
```

A release past EOL without ESM is the finding. `Unattended-Upgrade "0"`, or the file absent, is the finding. A container answers neither question the way the robot does — record undecided rather than a pass.

### B.0.4 Disk encrypted, boot locked

`Cons (enabler)` · `T T4` · `P P3` · `X X3`

**Weakness.** Unencrypted rootfs, no Secure Boot, BIOS or GRUB unlocked, exposed debug headers

**Path to effect.** Physical access to a parked robot yields keystore extraction, so E5 fleet-wide, plus a persistent implant. An Ubuntu install is unencrypted unless LUKS was chosen at install time, and it sets no bootloader password.

```sh
$RUN lsblk -o NAME,FSTYPE,TYPE,MOUNTPOINT
$RUN mokutil --sb-state
```

No `crypto_LUKS` in the tree is an unencrypted rootfs, which is the finding and is what an Ubuntu install gives unless LUKS was chosen at install time. `SecureBoot disabled` is the finding. Bootloader password and debug headers are physical checks, not commands.

### B.0.5 Package sources authenticated

`Cons (enabler)` · `T T1` · `P P2` · `X X2`

**Weakness.** `deb http://` sources, third-party PPAs, `curl` piped to `sudo bash` install scripts, unsigned or unpinned container images, `pip install` as root into the system Python that ROS uses

**Path to effect.** Build-time or update-time code execution as root. The compromise arrives through the maintenance channel.

```sh
$RUN grep -RhE '^deb|^URIs' /etc/apt/sources.list /etc/apt/sources.list.d/
```

Any `http://` is the finding. So is an unpinned third-party PPA. The `curl | sudo bash` and `pip install` as root halves of this leaf leave no artefact to grep — ask for the provisioning scripts.

**Example**, the lab in any posture:

```
URIs: http://archive.ubuntu.com/ubuntu/
URIs: http://security.ubuntu.com/ubuntu/
URIs: http://packages.ros.org/ros2/ubuntu
```

### B.0.6 Firewall active, network segmented

`Cons (enabler)` · `T T1` · `P P3` · `X X3`

**Weakness.** Robots on the same flat network as office IT, `ufw` inactive, one WPA2-PSK for the whole fleet, no 802.1X

**Path to effect.** Any compromised laptop reaches the robot's DDS ports, UDP from 7400 + 250 × domain ID, and its management interfaces. It also removes the physically-isolated-network assumption that many ROS deployments rely on in place of DDS-Security.

```sh
$RUN systemctl is-active ufw
$RUN ss -tulnH
$RUN ip -br addr
```

`inactive` is the finding. The segmentation half is not answerable from the host alone: a robot on the same subnet as office IT is a finding about the network, evidenced from your own position — if your unprivileged laptop reached the robot's RTPS ports at all, that is the evidence.

**Mitigations** 
- SSH keys only, with no password auth, no root login, and per-robot keys. 
- Bind nothing but the required ROS ports, and put rosbridge and teleop behind authenticated mTLS or remove them in production. 
- Run `unattended-upgrades` on a supported release with a patch SLA. 
- Use full-disk encryption with the key sealed to a TPM, Secure Boot, a locked bootloader and disabled debug headers. 
- Sign OTA updates and support rollback. 
- Put robots on their own VLAN with 802.1X and an egress-filtered firewall.

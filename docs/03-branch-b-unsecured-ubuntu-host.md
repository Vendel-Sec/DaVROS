## 3. Branch B, unsecured Ubuntu host

```mermaid
graph LR
    B["B Compromise the<br/>Ubuntu host [SAND]"]
    B --> B0["B.0 Initial access [OR]<br/>T1 to T4"]
    B --> B1["B.1 Hold the privileges that own<br/>the DDS credentials [OR]<br/>T3"]
    B --> B2["B.2 Convert to ROS compromise [OR]<br/>T3 to T4"]

    B0 --> B01["B.0.1 SSH: password auth, default or weak<br/>credentials, image-baked authorized_keys"]
    B0 --> B02["B.0.2 Exposed unauthenticated services:<br/>rosbridge websocket, web teleop UI,<br/>VNC, MQTT, Docker API 2375"]
    B0 --> B03["B.0.3 Unpatched Ubuntu:<br/>no unattended-upgrades, EOL release, no ESM"]
    B0 --> B04["B.0.4 Physical: no LUKS, no Secure Boot,<br/>USB or GRUB single-user boot, open UART or JTAG"]
    B0 --> B05["B.0.5 Supply chain: apt over http, unpinned PPAs,<br/>curl-pipe-sudo installers, unsigned container images,<br/>pip install as root"]
    B0 --> B06["B.0.6 Network: flat, no VLAN, ufw inactive,<br/>WPA2-PSK shared across the fleet, no 802.1X"]

    B1 --> B10["B.1.0 No escalation required,<br/>ROS already runs as the user<br/>the attacker controls"]
    B1 --> B11["B.1.1 ROS user in sudo NOPASSWD or docker group"]
    B1 --> B12["B.1.2 Writable systemd unit for the ROS launch service"]
    B1 --> B13["B.1.3 World-writable colcon workspace,<br/>install/setup.bash gives code exec as the ROS user"]
    B1 --> B14["B.1.4 Unpatched kernel local privesc"]
    B1 --> B15["B.1.5 SUID or capability-laden binaries<br/>from vendor drivers"]

    B2 --> B21["B.2.1 Read the keystore private keys,<br/>legitimate participant here and fleet-wide"]
    B2 --> B22["B.2.2 Flip the environment: drop ROS_SECURITY_ENABLE<br/>or set Permissive in the unit file"]
    B2 --> B23["B.2.3 Replace governance or permissions,<br/>with the CA key left on the robot"]
    B2 --> B24["B.2.4 In-process attack: LD_PRELOAD, ptrace,<br/>swap the node binary or Python entry point,<br/>ros2 param set on safety limits"]
    B2 --> B25["B.2.5 Shift the clock via unauthenticated NTP,<br/>break or extend cert and permissions validity"]
    B2 --> B26["B.2.6 /dev/shm segments of the SHM transport<br/>readable or writable by any local user"]
    B2 --> B27["B.2.7 No auditd, no remote logging,<br/>persistence undetected"]
```

> **On the gate.** B is a sequential AND, so all three conjuncts must hold, and in the order drawn. B.0 and B.1 reach no consequence on their own, so their `Cons` value is `(enabler)`, with one exception: B.0.2, an unauthenticated rosbridge, is a direct ROS read and write path and reaches E1 to E3 by itself.

| Part | Group | Leaves | T |
|---|---|---|---|
| [B.0](03-branch-b/b0-initial-access.md) | Initial access | B.0.1 to B.0.6 | T1 to T4 |
| [B.1](03-branch-b/b1-privileges.md) | Holding the privileges that own the DDS credentials | B.1.0 to B.1.5 | T3 |
| [B.2](03-branch-b/b2-ros-compromise.md) | Converting host access into ROS compromise | B.2.1 to B.2.7 | T3 to T4 |

Branch B commands run through `$RUN`, the transport that reaches the host: `ssh user@robot` on an engagement, `ssh -F /target-access/ssh_config davros-target sudo -n` in the lab.

## Sources

- [OpenSSH `sshd_config`](https://man.openbsd.org/sshd_config)
- [Ubuntu Server, OpenSSH server](https://ubuntu.com/server/docs/how-to/security/openssh-server/)
- [Ubuntu Server, automatic updates](https://documentation.ubuntu.com/server/how-to/software/automatic-updates/)
- [cloud-init, users and groups module](https://cloudinit.readthedocs.io/en/latest/reference/modules.html#users-and-groups)
- [`systemd.exec`](https://www.freedesktop.org/software/systemd/man/latest/systemd.exec.html)
- [`systemd-timesyncd.service`](https://www.freedesktop.org/software/systemd/man/latest/systemd-timesyncd.service.html)
- [RFC 8915, Network Time Security](https://www.rfc-editor.org/rfc/rfc8915.html)
- [Linux kernel, Yama LSM `ptrace_scope`](https://www.kernel.org/doc/html/latest/admin-guide/LSM/Yama.html)
- [Fast DDS v2.14.6, Shared memory transport](https://fast-dds.docs.eprosima.com/en/v2.14.6/fastdds/transport/shared_memory/shared_memory.html)
- [Cyclone DDS, Shared memory exchange](https://cyclonedds.io/docs/cyclonedds/latest/shared_memory/shared_memory.html)
- [rosbridge_suite](https://github.com/RobotWebTools/rosbridge_suite)
- [ROS 2 Jazzy, Security deployment guidelines](https://docs.ros.org/en/jazzy/Tutorials/Advanced/Security/Deployment-Guidelines.html)
- Kordy, B., Mauw, S., Radomirovic, S. and Schweitzer, P. ["Foundations of Attack-Defense Trees"](https://doi.org/10.1007/978-3-642-19751-2_6), FAST 2010

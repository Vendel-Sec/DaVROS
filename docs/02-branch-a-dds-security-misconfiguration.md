## 2. Branch A, DDS-Security plugin misconfiguration

Branch A is an `[OR]` over five groups, one file each. Every leaf carries the command that decides it from a terminal, or says it is a process control with no command (A.1.2, A.4.4, A.4.5), and real output from the lab where the lab can produce it.

| Part | Group | Leaves | T |
|---|---|---|---|
| [A.0](02-branch-a/a0-security-layer.md) | Security layer not in force | A.0.1 to A.0.6 | T1 to T3 |
| [A.1](02-branch-a/a1-authentication.md) | Defeat participant authentication, `DDS:Auth:PKI-DH` | A.1.1 to A.1.10 | T1 to T3 |
| [A.2](02-branch-a/a2-wire-crypto.md) | Defeat confidentiality and integrity on the wire, `DDS:Crypto:AES-GCM-GMAC` | A.2.1 to A.2.8 | T1 to T2 |
| [A.3](02-branch-a/a3-authorization.md) | Defeat authorization, `DDS:Access:Permissions` | A.3.1 to A.3.17 | T1 to T3 |
| [A.4](02-branch-a/a4-artefact-delivery.md) | Subvert delivery of the security artefacts | A.4.1 to A.4.5 | T1 to T3 |

> A clean branch A says nothing about a host the attacker owns. [Section 4](04-the-critical-observation.md).

## Sources

- [OMG DDS-Security v1.1](https://www.omg.org/spec/DDS-SECURITY/1.1/PDF)
- [Fast DDS v2.14.6, Authentication plugin: DDS:Auth:PKI-DH](https://fast-dds.docs.eprosima.com/en/v2.14.6/fastdds/security/auth_plugin/auth_plugin.html)
- [Fast DDS v2.14.6, Access control plugin: DDS:Access:Permissions](https://fast-dds.docs.eprosima.com/en/v2.14.6/fastdds/security/access_control_plugin/access_control_plugin.html)
- [Fast DDS v2.14.6, Cryptographic plugin: DDS:Crypto:AES-GCM-GMAC](https://fast-dds.docs.eprosima.com/en/v2.14.6/fastdds/security/crypto_plugin/crypto_plugin.html)
- [Fast DDS v2.14.6, XML profiles](https://fast-dds.docs.eprosima.com/en/v2.14.6/fastdds/xml_configuration/xml_configuration.html)
- [Fast DDS v2.14.6, Environment variables](https://fast-dds.docs.eprosima.com/en/v2.14.6/fastdds/env_vars/env_vars.html)
- [Cyclone DDS, DDS Security](https://cyclonedds.io/docs/cyclonedds/latest/security/dds_security.html)
- [Cyclone DDS 0.10.x (Jazzy), Configuration options, `//CycloneDDS/Domain/Security`](https://github.com/eclipse-cyclonedds/cyclonedds/blob/releases/0.10.x/docs/manual/options.md)
- [ROS 2 design, DDS-Security integration](https://design.ros2.org/articles/ros2_dds_security.html)
- [ROS 2 Jazzy, Setting up security](https://docs.ros.org/en/jazzy/Tutorials/Advanced/Security/Introducing-ros2-security.html)
- [ROS 2 Jazzy, Understanding the security keystore](https://docs.ros.org/en/jazzy/Tutorials/Advanced/Security/The-Keystore.html)
- [ROS 2 Jazzy, Security deployment guidelines](https://docs.ros.org/en/jazzy/Tutorials/Advanced/Security/Deployment-Guidelines.html)
- [`systemd.exec`](https://www.freedesktop.org/software/systemd/man/latest/systemd.exec.html)
- Kordy, B., Mauw, S., Radomirovic, S. and Schweitzer, P. ["Foundations of Attack-Defense Trees"](https://doi.org/10.1007/978-3-642-19751-2_6), FAST 2010

sros2 0.13.6 as installed, ROS 2 Jazzy:

- [`sros2/policy/defaults/dds/governance.xml`](https://github.com/ros2/sros2/blob/jazzy/sros2/sros2/policy/defaults/dds/governance.xml)
- [`sros2/policy/defaults/policy.xml`](https://github.com/ros2/sros2/blob/jazzy/sros2/sros2/policy/defaults/policy.xml)
- [`sros2/policy/templates/dds/permissions.xsl`](https://github.com/ros2/sros2/blob/jazzy/sros2/sros2/policy/templates/dds/permissions.xsl)
- [`sros2/keystore/_permission.py`](https://github.com/ros2/sros2/blob/jazzy/sros2/sros2/keystore/_permission.py)
- [`sros2/_utilities.py`](https://github.com/ros2/sros2/blob/jazzy/sros2/sros2/_utilities.py)

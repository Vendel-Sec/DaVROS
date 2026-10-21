# Attack Tree, ROS 2 Robotic System

**Scope:** ROS 2 node graph over DDS (RMW is Fast DDS by default, with Cyclone DDS and Zenoh equivalents given per leaf; parameters kept vendor-agnostic per OMG DDS-Security 1.1 where possible), running on an Ubuntu host.
**Focus branches:** 
(A) misconfiguration of the DDS-Security authentication, cryptographic and access-control plugins, one path per parameter. 
(B) an unsecured Ubuntu host underneath ROS.

---

## Contents

- [0. Conventions, attacker profiles and scope](docs/00-conventions-and-scope.md)
- [1. Top-level tree](docs/01-top-level-tree.md)
- [2. Branch A, DDS-Security plugin misconfiguration](docs/02-branch-a-dds-security-misconfiguration.md)
  - [2.0 A.0 Security layer not in force](docs/02-branch-a/a0-security-layer.md)
  - [2.1 A.1 Defeat participant authentication](docs/02-branch-a/a1-authentication.md)
  - [2.2 A.2 Defeat confidentiality and integrity on the wire](docs/02-branch-a/a2-wire-crypto.md)
  - [2.3 A.3 Defeat authorization](docs/02-branch-a/a3-authorization.md)
  - [2.4 A.4 Subvert delivery of the security artefacts](docs/02-branch-a/a4-artefact-delivery.md)
- [3. Branch B, unsecured Ubuntu host](docs/03-branch-b-unsecured-ubuntu-host.md)
  - [3.0 B.0 Initial access](docs/03-branch-b/b0-initial-access.md)
  - [3.1 B.1 Holding the privileges that own the DDS credentials](docs/03-branch-b/b1-privileges.md)
  - [3.2 B.2 Converting host access into ROS compromise](docs/03-branch-b/b2-ros-compromise.md)
- [4. The critical observation](docs/04-the-critical-observation.md)
- [5. Suggested assessment order](docs/05-suggested-assessment-order.md)
- [6. Cross-distro targets](docs/06-cross-distro-targets.md)
- [7. DaVROS topology](docs/07-davros-topology.md)

## 0. Conventions, attacker profiles and scope

### 0.1 Notation

| Symbol | Meaning |
|---|---|
| `[OR]` | Any one child achieves the parent goal. |
| `[AND]` | Every child required. |
| `[SAND]` | Every child required, in the order drawn (sequential AND) |
| `P` | Source of the predisposing condition, `P1` to `P3`, from section 0.2 |
| `X` | Attack complexity once present, from section 0.3 |
| `T` | The weakest attacker profile that suffices, `T1` to `T4`, from section 0.4. On a group, the range its leaves span |
| `Cons` | Consequence classes this leaf reaches, from section 0.5. |
| Leaf ID | `A.x.y` for a DDS-Security misconfiguration, `B.x.y` for the Ubuntu host. A leaf's heading names the control that passes, and its node in a tree diagram names the weakness that fails it. |

**Root goal G0:** Attacker gains unauthorized control over, or unauthorized visibility into, the robot's ROS 2 graph.

### 0.2 Attribute P, source of the predisposing condition

Every leaf in this tree is a **predisposing condition** in the sense of NIST SP 800-30 Rev. 1: 

> A predisposing condition is a condition that exists within an organization, a mission or business process, enterprise architecture, information system, or environment of operation, which affects (i.e., increases or decreases) the likelihood that threat events, once initiated, result in adverse impacts to organizational operations and assets, individuals, other organizations, or the Nation.

`P` records where that condition came from, which is what makes it prevalent.

| ID | Source of the condition | What it takes to be in this state |
|---|---|---|
| **P3** | Insecure default | Present with no configuration action at all, or emitted by the provisioning tooling's own default output, so it is what an unhardened deployment runs. |
| **P2** | Misconfiguration through the supported path | A wrong choice available *through* that tooling, the `ros2 security` verbs for branch A and the packaged install and ordinary administration path for branch B. |
| **P1** | Misconfiguration by hand | Reachable only by hand-editing an artefact the tooling generated, or by replacing it with a hand-written equivalent. |

**Weakness classes associated with insecure defaults:** 

| CWE | Leaves |
|---|---|
| CWE-1188, Initialization of a Resource with an Insecure Default | A.1.5, A.1.6, A.1.7, A.1.9, A.2.7, A.2.8, A.3.8, A.3.10, A.3.12, A.3.13, A.3.15, A.4.3, A.4.5 |
| CWE-453, Insecure Default Variable Initialization | A.0.1, A.0.2, A.0.6 |
| CWE-276, Incorrect Default Permissions | A.4.2 |
| CWE-732, Incorrect Permission Assignment for Critical Resource | B.1.1, B.1.3, B.2.1 |
| CWE-1392, Use of Default Credentials | B.0.1 |

### 0.3 Attribute X, attack complexity

Attack complexity once the condition is present. 

CVSS v4.0 splits this across two base metrics: 
- Attack Complexity (AC), "measurable actions that must be taken by the attacker to actively evade or circumvent existing built-in security-enhancing conditions", 
- Attack Requirements (AT), "prerequisite deployment and execution conditions or variables of the vulnerable system that enable the attack". 

`X` is the ordinal collapse of the two.

| ID | CVSS v4.0 | Meaning |
|---|---|---|
| **X3** | `AC:L/AT:N` | Single-step, with no built-in security-enhancing condition to evade and no prerequisite beyond the profile in `T`. |
| **X2** | `AC:H/AT:N` | Requires evading a built-in security-enhancing condition, or knowledge of the node graph obtained by reconnaissance. |
| **X1** | `AT:P` | Requires a prerequisite deployment or execution condition outside the attacker's control, such as a race or physical presence. |

**Position and privilege are not in `X`.** They are in `T`, which carries the CVSS Attack Vector and Privileges Required metrics, see section 0.4. 

### 0.4 Attacker profiles

Four profiles are used. The `CVSS v4.0` column gives the Attack Vector and Privileges Required metrics each profile corresponds to, so that position and privilege are recorded here and not in `X`.

| ID | Profile | CVSS v4.0 | Position and capability |
|---|---|---|---|
| **T1** | Network adjacent, unauthenticated | `AV:A/PR:N` | Can send and receive on the robot's L2 (data link) / L3 (network) segment, including the RTPS ports (UDP 7400 + 250 × domain ID and up, 17900 to 18149 for the lab's domain 42) and any exposed management port. A compromised office laptop, a rogue Wi-Fi client, a contractor's machine on a flat network. | 
| **T2** | Authenticated participant, or a compromised low privilege node | `AV:A/PR:L` | Holds one valid enclave credential, such as a camera driver, a logger or a diagnostics node, and is therefore inside the DDS cryptographic trust boundary. | 
| **T3** | Local unprivileged host user | `AV:L/PR:L` | A shell as the ROS user or another local account, able to read whatever that user can read, which normally includes the keystore. | 
| **T4** | Root or physical | `AV:L/PR:H` or `AV:P` | Root on the host, or unsupervised physical access to a parked robot: USB boot, disk removal, debug headers. | 

### 0.5 Consequence classes and impact

Impact is a property of the consequence reached. The `Cons` field in each leaf's tag line points here.

| ID | Consequence | Impact | Why that rating |
|---|---|---|---|
| **E1** | Command injection. Attacker publishes on an actuation topic, action or service. | **Critical** | Uncommanded motion of a physical machine. This consequence class has a direct route to human injury. |
| **E2** | Sensor or state falsification. Attacker publishes on a perception or state topic. | **Critical** | The robot acts on a false world model, so it produces unsafe motion through its own control loop. Reaches the same place as E1 while being harder to detect, because every component behaves correctly. |
| **E3** | Exfiltration. Attacker subscribes to camera, map, telemetry or mission data. | **High to Critical** | Loss of confidentiality of the site and the process. In some deployments, critical due to the classification of the data. |
| **E4** | Denial of service or forced safety stop. | **Medium to High** | Availability only. High where a stopped robot blocks a production line, the completion of the mission, Medium where it fails safe with no downstream effect.|
| **E5** | Persistence and fleet lateral movement. | **Critical** | Converts a single-robot compromise into an fleet compromise and removes eviction as an option. |

Nodes tagged `(enabler)` reach no consequence on their own. They satisfy a conjunct of the sequential AND.

### 0.6 Assumptions and scope exclusions

**Assumptions** 

- RMW is Fast DDS, the ROS 2 Jazzy default. Parameter names follow Fast DDS while the semantics follow OMG DDS-Security 1.1 and carry to any compliant RMW. Each leaf that reads a configuration setting also gives the Cyclone DDS (`rmw_cyclonedds_cpp`) and Zenoh (`rmw_zenoh_cpp`) equivalents, or says there is none. 
- One ROS domain and one robot are in scope. Fleet-wide consequences are recorded as E5, and A.1.3 and B.0.4 are where shared or unprotected identity material makes one robot the fleet. 
- The DDS-Security cryptographic primitives are assumed sound, so this tree models misconfiguration of the plugins and never cryptanalysis of AES-GCM/GMAC or ECDH.

**Out of scope** 

- Memory safety and logic vulnerabilities in the ROS 2 or Fast DDS source, so no CVE specific paths. 
- The fleet management or cloud backend, and any teleoperation path that does not terminate on this host. 
- RF, CAN bus, motor controller and other sub-ROS actuator attacks. 
- Upstream supply chain compromise of ROS packages, beyond the delivery weaknesses. 
- Social engineering of operators.



---

## Sources

- [OMG DDS-Security v1.1](https://www.omg.org/spec/DDS-SECURITY/1.1/PDF)
- [Fast DDS v2.14.6, Authentication plugin: DDS:Auth:PKI-DH](https://fast-dds.docs.eprosima.com/en/v2.14.6/fastdds/security/auth_plugin/auth_plugin.html)
- [Fast DDS v2.14.6, Access control plugin: DDS:Access:Permissions](https://fast-dds.docs.eprosima.com/en/v2.14.6/fastdds/security/access_control_plugin/access_control_plugin.html)
- [Fast DDS v2.14.6, Cryptographic plugin: DDS:Crypto:AES-GCM-GMAC](https://fast-dds.docs.eprosima.com/en/v2.14.6/fastdds/security/crypto_plugin/crypto_plugin.html)
- [Cyclone DDS, DDS Security](https://cyclonedds.io/docs/cyclonedds/latest/security/dds_security.html)
- [Cyclone DDS 0.10.x (Jazzy), Configuration options, `//CycloneDDS/Domain/Security`](https://github.com/eclipse-cyclonedds/cyclonedds/blob/releases/0.10.x/docs/manual/options.md)
- [CVSS v4.0 specification document](https://www.first.org/cvss/v4.0/specification-document), FIRST
- [NIST SP 800-30 Rev. 1, Guide for Conducting Risk Assessments](https://csrc.nist.gov/pubs/sp/800/30/r1/final)
- MITRE CWE 4.20: [CWE-1188](https://cwe.mitre.org/data/definitions/1188.html), [CWE-453](https://cwe.mitre.org/data/definitions/453.html), [CWE-276](https://cwe.mitre.org/data/definitions/276.html), [CWE-732](https://cwe.mitre.org/data/definitions/732.html), [CWE-1392](https://cwe.mitre.org/data/definitions/1392.html)
- Schneier, B. ["Attack Trees"](https://www.schneier.com/academic/archives/1999/12/attack_trees.html), Dr. Dobb's Journal, December 1999
- Mauw, S. and Oostdijk, M. ["Foundations of Attack Trees"](https://doi.org/10.1007/11734727_17), ICISC 2005
- Jhawar, R., Kordy, B., Mauw, S., Radomirovic, S. and Trujillo-Rasua, R. ["Attack Trees with Sequential Conjunction"](https://doi.org/10.1007/978-3-319-18467-8_23), IFIP SEC 2015

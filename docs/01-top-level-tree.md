## 1. Top-level tree

```mermaid
graph TD
    G0["G0 Unauthorized control of, or visibility into,<br/>the ROS 2 graph [OR]"]

    A["A Subvert the DDS-Security layer<br/>via misconfiguration [OR]"]
    B["B Compromise the Ubuntu host<br/>and inherit ROS trust [SAND]"]

    G0 --> A
    G0 --> B

    A0["A.0 Security layer not in force<br/>T1 to T3"]
    A1["A.1 Defeat participant authentication<br/>(DDS:Auth:PKI-DH)<br/>T1 to T3"]
    A2["A.2 Defeat confidentiality and integrity<br/>on the wire (DDS:Crypto:AES-GCM-GMAC)<br/>T1 to T2"]
    A3["A.3 Defeat authorization<br/>(DDS:Access:Permissions)<br/>T1 to T3"]
    A4["A.4 Subvert delivery of the security<br/>artefacts: keystore, XML profiles, CA<br/>T1 to T3"]

    A --> A0
    A --> A1
    A --> A2
    A --> A3
    A --> A4

    A1a["A.1a Become an authenticated participant"]
    A1b["A.1b Recover the session keys"]
    A1 --> A1a
    A1 --> A1b

    A3a["A.3a via governance"]
    A3b["A.3b via permissions"]
    A3 --> A3a
    A3 --> A3b

    B0["B.0 Initial access to the host<br/>T1 to T4"]
    B1["B.1 Hold the privileges that own<br/>the DDS credentials<br/>T3"]
    B2["B.2 Convert host access into<br/>ROS compromise<br/>T3 to T4"]

    B --> B0
    B --> B1
    B --> B2

    B2 -.->|"DOMINATES: host compromise voids<br/>every control in branch A"| A

    classDef goal fill:#7c2d12,stroke:#7c2d12,color:#fff
    classDef branch fill:#1e3a5f,stroke:#1e3a5f,color:#fff
    class G0 goal
    class A,B branch
```

> The dotted edge is the key structural point: **branch B dominates branch A.** A perfectly configured DDS-Security stack on a host the attacker owns provides no assurance, because the private keys, the governance document and the environment variables all live on that host.


---

## Sources

- [ROS 2 design, DDS-Security integration](https://design.ros2.org/articles/ros2_dds_security.html)
- [ROS 2 Jazzy, About security](https://docs.ros.org/en/jazzy/Concepts/Intermediate/About-Security.html)
- [OMG DDS-Security v1.1](https://www.omg.org/spec/DDS-SECURITY/1.1/PDF)
- Jhawar, R., Kordy, B., Mauw, S., Radomirovic, S. and Trujillo-Rasua, R. ["Attack Trees with Sequential Conjunction"](https://doi.org/10.1007/978-3-319-18467-8_23), IFIP SEC 2015

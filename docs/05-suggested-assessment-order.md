## 5. Suggested assessment order

| Priority | Check | Tree refs |
|---|---|---|
| 1 | Is security even on and enforcing? | A.0.1, A.0.2 |
| 2 | Where does the CA private key live? | A.3.15, A.4.3 |
| 3 | Are both signed documents actually signed and present? | A.3.16, A.3.17 |
| 4 | Keystore and key file permissions, is one identity shared across the fleet, and are the key sizes adequate? | A.1.3, A.1.4, A.1.10, A.4.2 |
| 5 | Grep governance and permissions for `NONE`, `*`, and `true` on the permissive switches | A.2.2 to A.2.6, A.3.2 to A.3.5, A.3.8, A.3.10, A.3.11 |
| 6 | Rule ordering in `topic_access_rules`, and is the `<default>` element present? | A.3.8, A.3.11 |
| 7 | Host: patch level, SSH configuration, exposed ports, `sudo` and `docker` group, disk encryption | B.0.1 to B.0.6, B.1.1 |
| 8 | Unit files and workspace ownership, and the source of truth for the environment variables | B.1.2, B.1.3, B.2.2 |
| 9 | Revocation, rotation, time source, logging | A.1.6, A.1.9, A.4.5, B.2.5, B.2.7 |

Note that steps 1 to 6 are all inside branch A and can be decided from the artefacts and the network, and steps 7 and 8 are inside branch B and need host access. Section 4 argues branch B should be assessed first. The ordering here is a report-writing order, working from the cheapest evidence to the most expensive, and it is not a statement about which findings matter most.

### Filtered views of the tree

The leaf attributes do not rank severity, section 0.5 does. What they support is a set of filtered views, each answering one question an assessor asks directly.

| Query | Answer from this tree |
|---|---|
| What is reachable by T1 alone, with no credential and no account? | A.0.1, A.0.2, A.0.5, A.0.6, A.1.1, A.1.2, A.1.7, A.1.8, A.1.10, all of A.2 except A.2.8, A.3.2, A.3.6, A.3.16, A.3.17, A.4.4, and B.0.1, B.0.2, B.0.3, B.0.5, B.0.6. That is 26 of 65 leaves. |
| Which leaves are `P3` and `X3` together, so present in the tooling's own output and single-step to exploit? | A.0.1, A.0.2, A.0.6, A.1.5, A.1.6, A.1.9, A.2.7, A.2.8, A.3.8, A.3.10, A.3.12, A.3.13, A.3.15, A.4.2, A.4.3, B.0.1, B.0.2, B.0.4, B.0.6, B.1.0, B.1.1, B.1.3, B.2.1, B.2.2, B.2.4, B.2.5, B.2.6, B.2.7. That is 28 of the 65 leaves. A filter, not a ranking: severity comes from the consequence, see section 0.5. |
| Which weaknesses did someone have to introduce by hand, and still reach E1 in one step? | The nine `P1 X3` leaves reaching E1: A.0.5, A.1.1, A.3.1, A.3.2, A.3.3, A.3.5, A.3.11, A.3.16, A.3.17. All but A.0.5 and A.1.1 are edits to the generated governance or permissions document, so a policy diff against the output of `create_keystore` and `create_enclave` finds every one of them. |
| Where does one control move the most? | At a SAND, a control on any single conjunct raises the bound for the whole branch. At an OR, a control raises nothing unless every sibling is covered. That is the argument for spending effort on B.1 and B.2 rather than on individual B.0 rows. |

---

## Sources

- [ROS 2 Jazzy, Setting up security](https://docs.ros.org/en/jazzy/Tutorials/Advanced/Security/Introducing-ros2-security.html)
- [ROS 2 Jazzy, Understanding the security keystore](https://docs.ros.org/en/jazzy/Tutorials/Advanced/Security/The-Keystore.html)
- [ROS 2 Jazzy, Security deployment guidelines](https://docs.ros.org/en/jazzy/Tutorials/Advanced/Security/Deployment-Guidelines.html)
- Mauw, S. and Oostdijk, M. ["Foundations of Attack Trees"](https://doi.org/10.1007/11734727_17), ICISC 2005
- Jhawar, R., Kordy, B., Mauw, S., Radomirovic, S. and Trujillo-Rasua, R. ["Attack Trees with Sequential Conjunction"](https://doi.org/10.1007/978-3-319-18467-8_23), IFIP SEC 2015

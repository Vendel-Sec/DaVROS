## 6. Cross-distro targets

**Builds and provisions on `humble`, `jazzy`, `kilted`, `lyrical`.** 

The attacker, `davros-attacker`, is always `jazzy`. Any other target distro makes the lab cross-distro: a check that joins the target's graph from `davros-attacker` then relies on `rclpy` and DDS interoperability between the two releases, and can fail for reasons that have nothing to do with the target's posture. Reading the artefacts, inspecting the host and capturing traffic are unaffected.

### Selecting the distro

`TARGET_ROS_DISTRO` is a build argument on the simulated target, default `jazzy`.

```
TARGET_ROS_DISTRO=humble docker compose \
    build target
TARGET_ROS_DISTRO=humble docker compose \
    up -d --force-recreate --wait target peer
```

| Distro | Python |
|---|---|
| `humble` | 3.10 |
| `jazzy` | 3.12, default |
| `kilted` | 3.12 |
| `lyrical` | 3.14 |

For now, no other value is supported: the provisioner needs ROS 2 and Python 3.10 or newer.


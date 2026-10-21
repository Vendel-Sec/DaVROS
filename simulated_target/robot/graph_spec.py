# ROS Humble ships Python 3.10, where enum.StrEnum does not exist yet.

from enum import Enum

from pydantic import BaseModel, ConfigDict


class Role(str, Enum):  # noqa: UP042
    """What a topic carries, which decides which consequence class a forged or"""
    ACTUATION = "actuation"   # E1, a forged message here is motion
    SENSOR = "sensor"         # E2, a forged message here is a false world model
    STATE = "state"           # E2, same, via the robot's own control loop
    MISSION = "mission"       # E3, site and process confidentiality
    OTHER = "other"


class Topic(BaseModel):
    model_config = ConfigDict(frozen=True)

    name: str                 # ROS name, e.g. "cmd_vel"
    type: str                 # e.g. "geometry_msgs/msg/Twist"
    role: Role = Role.OTHER

    @property
    def dds_name(self) -> str:
        """The DDS topic name, which governance expressions match against."""
        return f"rt/{self.name}"

    @property
    def ros_name(self) -> str:
        """The fully qualified ROS name, which is what a check subscribes to."""
        return f"/{self.name}"


class Service(BaseModel):
    model_config = ConfigDict(frozen=True)

    name: str
    type: str


class NodeSpec(BaseModel):
    """One node: its identity, and exactly the topics it actually uses."""
    model_config = ConfigDict(frozen=True)

    name: str
    enclave: str
    publishes: tuple[str, ...] = ()
    subscribes: tuple[str, ...] = ()
    replies: tuple[str, ...] = ()
    host: str = "robot"
    note: str = ""


TOPICS: tuple[Topic, ...] = (
    Topic(name="cmd_vel", type="geometry_msgs/msg/Twist", role=Role.ACTUATION),
    Topic(name="goal_pose", type="geometry_msgs/msg/PoseStamped", role=Role.ACTUATION),
    Topic(name="scan", type="sensor_msgs/msg/LaserScan", role=Role.SENSOR),
    Topic(name="odom", type="nav_msgs/msg/Odometry", role=Role.STATE),
    Topic(name="tf", type="tf2_msgs/msg/TFMessage", role=Role.STATE),
    Topic(name="map", type="nav_msgs/msg/OccupancyGrid", role=Role.MISSION),
    Topic(name="robot_state", type="std_msgs/msg/String", role=Role.STATE),
    Topic(name="chatter", type="std_msgs/msg/String", role=Role.OTHER),
)

SERVICES: tuple[Service, ...] = (
    Service(name="diagnostics/self_test", type="std_srvs/srv/Trigger"),
)

NODES: tuple[NodeSpec, ...] = (
    NodeSpec(
        name="scan_publisher", enclave="/scan_publisher",
        publishes=("scan",),
        note="The credential the attacker holds for T2 work: the tree's "
             "'camera driver, logger or diagnostics node'.",
    ),
    NodeSpec(
        name="motion_controller", enclave="/motion_controller",
        subscribes=("cmd_vel",), publishes=("odom", "robot_state"),
        note="The actuation consumer, and the witness for every write-match "
             "check. Its subscription either matches an attacker's writer or it "
             "does not, which answers the access-control question with no "
             "payload sent.",
    ),
    NodeSpec(
        name="odom_publisher", enclave="/odom_publisher",
        publishes=("tf",),
    ),
    NodeSpec(
        name="mission_planner", enclave="/mission_planner", host="peer",
        publishes=("goal_pose", "cmd_vel"), subscribes=("map", "odom"),
        note="Holds the safety parameters a B.2.4 check targets. It is also the "
             "one node legitimately permitted to write cmd_vel.",
    ),
    NodeSpec(name="talker", enclave="/talker", publishes=("chatter",)),
    NodeSpec(name="listener", enclave="/listener", host="peer",
             subscribes=("chatter",)),
    NodeSpec(
        name="diagnostics", enclave="/diagnostics",
        subscribes=("robot_state",), replies=("diagnostics/self_test",),
        note="Exercises a service grant, so the A.3 checks are not topic-only.",
    ),
)

# A.3.13 and A.0.4: the enclave every node collapses into when per-node
# segmentation is turned off.
SHARED_ENCLAVE = "/robot"

# Safety-relevant parameters, for the B.2.4 checks. A limit changed here takes
# effect inside the target process, after decryption, which is why DDS-Security
# does not stop it.
SAFETY_PARAMETERS: tuple[tuple[str, str], ...] = (
    ("/motion_controller", "max_velocity"),
    ("/motion_controller", "geofence_radius"),
    ("/motion_controller", "watchdog_timeout"),
    ("/motion_controller", "estop_engaged"),
    ("/mission_planner", "max_velocity"),
)


def topic(name: str) -> Topic:
    for t in TOPICS:
        if t.name == name:
            return t
    raise KeyError(f"no topic named {name!r} in the graph spec")


def node(name: str) -> NodeSpec:
    for n in NODES:
        if n.name == name:
            return n
    raise KeyError(f"no node named {name!r} in the graph spec")


def enclaves() -> tuple[str, ...]:
    return tuple(n.enclave for n in NODES)


def topics_by_role(role: Role) -> tuple[Topic, ...]:
    return tuple(t for t in TOPICS if t.role is role)


def merged_node() -> NodeSpec:
    """The single omnipotent node a shared enclave collapses the graph into."""
    return NodeSpec(
        name="robot",
        enclave=SHARED_ENCLAVE,
        publishes=tuple(sorted({t for n in NODES for t in n.publishes})),
        subscribes=tuple(sorted({t for n in NODES for t in n.subscribes})),
        replies=tuple(sorted({s for n in NODES for s in n.replies})),
        note="One identity holding the union of every grant.",
    )

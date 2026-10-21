import math

from geometry_msgs.msg import PoseStamped, TransformStamped, Twist
from nav_msgs.msg import OccupancyGrid, Odometry
from rclpy.node import Node
from sensor_msgs.msg import LaserScan
from std_msgs.msg import String
from std_srvs.srv import Trigger
from tf2_msgs.msg import TFMessage


class ScanPublisher(Node):
    """A sensor driver. Its enclave is the credential handed to the T2 attacker."""

    def __init__(self) -> None:
        super().__init__("scan_publisher")
        self.declare_parameter("range_max", 12.0)
        self.pub = self.create_publisher(LaserScan, "scan", 10)
        self.i = 0
        self.create_timer(0.1, self.tick)

    def tick(self) -> None:
        msg = LaserScan()
        msg.header.stamp = self.get_clock().now().to_msg()
        msg.header.frame_id = "laser"
        msg.angle_min, msg.angle_max = -math.pi / 2, math.pi / 2
        msg.angle_increment = math.pi / 180.0
        msg.range_min = 0.05
        msg.range_max = float(self.get_parameter("range_max").value)
        count = int((msg.angle_max - msg.angle_min) / msg.angle_increment) + 1
        msg.ranges = [2.0 + math.sin((self.i + k) / 20.0) for k in range(count)]
        self.pub.publish(msg)
        self.i += 1


class MotionController(Node):
    """The actuation consumer, and the witness for every write-match check."""

    def __init__(self) -> None:
        super().__init__("motion_controller")
        self.declare_parameter("max_velocity", 0.5)
        self.declare_parameter("geofence_radius", 10.0)
        self.declare_parameter("watchdog_timeout", 0.5)
        self.declare_parameter("estop_engaged", False)
        self.sub = self.create_subscription(Twist, "cmd_vel", self.on_cmd, 10)
        self.odom_pub = self.create_publisher(Odometry, "odom", 10)
        self.state_pub = self.create_publisher(String, "robot_state", 10)
        self.x = 0.0
        self.commands = 0
        self.create_timer(0.1, self.tick)
        self.create_timer(1.0, self.publish_odom)

    def publish_odom(self) -> None:
        odom = Odometry()
        odom.header.stamp = self.get_clock().now().to_msg()
        odom.header.frame_id = "odom"
        odom.child_frame_id = "base_link"
        odom.pose.pose.position.x = self.x
        odom.pose.pose.orientation.w = 1.0
        self.odom_pub.publish(odom)

    def on_cmd(self, msg: Twist) -> None:
        self.commands += 1
        limit = float(self.get_parameter("max_velocity").value)
        self.get_logger().warning(
            f"COMMAND ACCEPTED #{self.commands}: linear.x={msg.linear.x:.3f} "
            f"angular.z={msg.angular.z:.3f} (max_velocity={limit}). "
            "On a real machine this is motion."
        )
        self.x += max(-limit, min(limit, msg.linear.x)) * 0.1

    def tick(self) -> None:
        self.state_pub.publish(
            String(data=f"ok commands={self.commands} x={self.x:.2f}")
        )


class OdomPublisher(Node):
    """State topics. /odom and /tf are the E2 sensor-falsification surface."""

    def __init__(self) -> None:
        super().__init__("odom_publisher")
        self.tf_pub = self.create_publisher(TFMessage, "tf", 10)
        self.t = 0.0
        self.create_timer(0.05, self.tick)

    def tick(self) -> None:
        self.t += 0.05
        x = math.sin(self.t / 5.0)

        tr = TransformStamped()
        tr.header.stamp = self.get_clock().now().to_msg()
        tr.header.frame_id = "odom"
        tr.child_frame_id = "base_link"
        tr.transform.translation.x = x
        tr.transform.rotation.w = 1.0
        self.tf_pub.publish(TFMessage(transforms=[tr]))


class MissionPlanner(Node):
    """Holds the safety parameters a B.2.4 check targets, and is the one node"""

    def __init__(self) -> None:
        super().__init__("mission_planner")
        self.declare_parameter("mission_id", "site-survey-01")
        self.declare_parameter("max_velocity", 0.5)
        self.declare_parameter("geofence_radius", 10.0)
        self.goal_pub = self.create_publisher(PoseStamped, "goal_pose", 10)
        self.cmd_pub = self.create_publisher(Twist, "cmd_vel", 10)
        self.create_subscription(Odometry, "odom", self.on_odom, 10)
        self.create_subscription(OccupancyGrid, "map", self.on_map, 10)
        self.n = 0
        self.create_timer(2.0, self.tick)

    def on_odom(self, msg: Odometry) -> None:
        self.get_logger().info(
            f"planner: robot at x={msg.pose.pose.position.x:.2f} "
            f"frame={msg.header.frame_id}"
        )

    def on_map(self, msg: OccupancyGrid) -> None:
        pass

    def tick(self) -> None:
        self.n += 1
        goal = PoseStamped()
        goal.header.stamp = self.get_clock().now().to_msg()
        goal.header.frame_id = "map"
        goal.pose.position.x = float(self.n % 5)
        goal.pose.orientation.w = 1.0
        self.goal_pub.publish(goal)
        self.cmd_pub.publish(Twist())


class Talker(Node):
    def __init__(self) -> None:
        super().__init__("talker")
        self.pub = self.create_publisher(String, "chatter", 10)
        self.i = 0
        self.create_timer(0.5, self.tick)

    def tick(self) -> None:
        self.i += 1
        battery = max(100 - self.i // 60, 15)
        self.pub.publish(String(data=(
            f"health seq={self.i} battery={battery}% temp=41C motors=ok estop=released"
        )))


class Listener(Node):
    def __init__(self) -> None:
        super().__init__("listener")
        self.create_subscription(String, "chatter", self.on_msg, 10)
        self.count = 0

    def on_msg(self, msg: String) -> None:
        self.count += 1
        if self.count % 20 == 1:
            self.get_logger().info(f"heard: {msg.data}")


class Diagnostics(Node):
    """Exercises a service grant, so the A.3 checks are not topic-only."""

    def __init__(self) -> None:
        super().__init__("diagnostics")
        self.create_subscription(String, "robot_state", self.on_state, 10)
        self.srv = self.create_service(Trigger, "diagnostics/self_test", self.on_test)
        self.last = ""

    def on_state(self, msg: String) -> None:
        self.last = msg.data

    def on_test(
        self, request: Trigger.Request, response: Trigger.Response,
    ) -> Trigger.Response:
        response.success = True
        response.message = f"last state: {self.last or 'none'}"
        return response


# Keys must match NodeSpec.name in graph_spec.py.
NODE_TYPES: dict[str, type[Node]] = {
    "scan_publisher": ScanPublisher,
    "motion_controller": MotionController,
    "odom_publisher": OdomPublisher,
    "mission_planner": MissionPlanner,
    "talker": Talker,
    "listener": Listener,
    "diagnostics": Diagnostics,
}

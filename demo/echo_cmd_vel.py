#!/usr/bin/env python3
import rclpy
from rclpy.node import Node
from rclpy.parameter import Parameter
from geometry_msgs.msg import Twist

rclpy.init()
node = Node(
    'cmd_vel_eavesdropper',
    start_parameter_services=False,
    parameter_overrides=[Parameter('start_type_description_service', value=False)],
)
node.create_subscription(Twist, '/cmd_vel', lambda m: print(m), 10)
rclpy.spin(node)

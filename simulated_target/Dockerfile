# Simulated ROS 2 target: the robot, and the image its peer runs.
#
#   docker build -f simulated_target/Dockerfile \
#       --build-arg ROS_DISTRO=humble -t davros-target:humble .
#
# Built and provisioned on humble, jazzy, kilted and lyrical, which is Python
# 3.10 to 3.14.
ARG ROS_DISTRO=jazzy
FROM ros:${ROS_DISTRO}-ros-base

ARG DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
        ros-${ROS_DISTRO}-sros2 \
        ros-${ROS_DISTRO}-rmw-fastrtps-cpp \
        ros-${ROS_DISTRO}-rmw-cyclonedds-cpp \
        ros-${ROS_DISTRO}-geometry-msgs \
        ros-${ROS_DISTRO}-sensor-msgs \
        ros-${ROS_DISTRO}-nav-msgs \
        ros-${ROS_DISTRO}-tf2-msgs \
        ros-${ROS_DISTRO}-rosbridge-suite \
        openssl \
        iproute2 \
        procps \
    && rm -rf /var/lib/apt/lists/*

# rmw_zenoh, where the distro has it. Humble's is wire-incompatible with later distros.
RUN apt-get update \
    && if apt-cache show ros-${ROS_DISTRO}-zenoh-security-tools >/dev/null 2>&1; then \
        apt-get install -y --no-install-recommends \
            ros-${ROS_DISTRO}-rmw-zenoh-cpp ros-${ROS_DISTRO}-zenoh-security-tools; \
    else echo "no rmw_zenoh packages for ${ROS_DISTRO}, TARGET_RMW=rmw_zenoh_cpp unavailable"; fi \
    && rm -rf /var/lib/apt/lists/*

# One interpreter for both the provisioner and the robot graph.
#
# --system-site-packages: rclpy is not on PyPI, it is found in the PYTHONPATH
COPY --from=ghcr.io/astral-sh/uv:0.5.11 /uv /usr/local/bin/uv
RUN uv venv /opt/davros/venv --system-site-packages --python /usr/bin/python3 \
    && UV_LINK_MODE=copy uv pip install --python /opt/davros/venv/bin/python \
        "pydantic>=2.6" "pydantic-settings>=2.2" "pyyaml>=6.0"

COPY simulated_target/__init__.py   /opt/davros/simulated_target/
COPY simulated_target/provisioning  /opt/davros/simulated_target/provisioning
COPY simulated_target/robot         /opt/davros/simulated_target/robot
COPY simulated_target/entrypoint.sh /opt/davros/entrypoint.sh
COPY simulated_target/rosbridge.sh  /opt/davros/rosbridge.sh
COPY simulated_target/peer.sh    /opt/davros/peer.sh


ENV PYTHONPATH=/opt/davros:${PYTHONPATH}
RUN chmod +x /opt/davros/entrypoint.sh /opt/davros/rosbridge.sh /opt/davros/peer.sh

# A realistic robot does not run ROS as root. 
RUN useradd -m -u 1500 -s /bin/bash ros \
    && mkdir -p /keystore /opt/ros2_ws/install \
    && chown -R ros:ros /opt/ros2_ws \
    && printf 'source /opt/ros/%s/setup.bash\nPS1="ros@robot-01:~\$ "\n' "${ROS_DISTRO}" > /home/ros/.bashrc \
    && chown ros:ros /home/ros/.bashrc

# Hardened defaults. Every one of them is overridden by target.env.
ENV ROS_SECURITY_ENABLE=true \
    ROS_SECURITY_STRATEGY=Enforce \
    ROS_SECURITY_KEYSTORE=/keystore \
    RMW_IMPLEMENTATION=rmw_fastrtps_cpp \
    ROS_DOMAIN_ID=42

EXPOSE 9090
ENTRYPOINT ["/opt/davros/entrypoint.sh"]
CMD ["graph"]

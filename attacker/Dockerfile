# The attacker (davros-attacker): network adjacent to the robot, no credentials.

FROM ros:jazzy-ros-base

ARG DEBIAN_FRONTEND=noninteractive
ARG USERNAME=attacker
ARG UV_VERSION=0.5.11

RUN apt-get update && apt-get install -y --no-install-recommends \
        ros-jazzy-sros2 \
        ros-jazzy-rmw-fastrtps-cpp \
        ros-jazzy-rmw-cyclonedds-cpp \
        ros-jazzy-rmw-zenoh-cpp \
        ros-jazzy-demo-nodes-cpp \
        ros-jazzy-demo-nodes-py \
        ros-jazzy-geometry-msgs \
        ros-jazzy-sensor-msgs \
        ros-jazzy-nav-msgs \
        ros-jazzy-tf2-msgs \
        python3-venv \
        openssl \
        tcpdump \
        tshark \
        dsniff \
        iproute2 \
        iputils-ping \
        net-tools \
        dnsutils \
        openssh-client \
        git \
        curl \
        ca-certificates \
        less \
        vim-tiny \
        sudo \
        jq \
    && rm -rf /var/lib/apt/lists/*

COPY --from=ghcr.io/astral-sh/uv:0.5.11 /uv /uvx /usr/local/bin/

# websocat, a WebSocket client for B.0.2's rosbridge. Not packaged for Ubuntu,
# so a pinned release binary, checked against its hash.
ARG WEBSOCAT_VERSION=1.14.1
RUN case "$(dpkg --print-architecture)" in \
        amd64) arch=x86_64;  sha=66f8dd3a0394761556339117f8bb5123bddefd44e087af2a72ec22b0bd08d514 ;; \
        arm64) arch=aarch64; sha=711a69576a2ff473fb01a90ffafb571c2ed019e55479d7ae71b12c2eadeb7011 ;; \
        *) echo "no websocat build for $(dpkg --print-architecture)" >&2; exit 1 ;; \
    esac && \
    curl -fsSL -o /usr/local/bin/websocat \
        "https://github.com/vi/websocat/releases/download/v${WEBSOCAT_VERSION}/websocat.${arch}-unknown-linux-musl" && \
    echo "${sha}  /usr/local/bin/websocat" | sha256sum -c - && \
    chmod 0755 /usr/local/bin/websocat

# Ubuntu 24.04 already ships a uid 1000 account named "ubuntu". Reuse it.
RUN if id -u 1000 >/dev/null 2>&1; then \
        old="$(id -un 1000)"; \
        if [ "$old" != "${USERNAME}" ]; then \
            usermod -l "${USERNAME}" "$old" && \
            groupmod -n "${USERNAME}" "$(id -gn 1000)" && \
            usermod -d "/home/${USERNAME}" -m "${USERNAME}"; \
        fi; \
    else \
        groupadd -g 1000 "${USERNAME}" && \
        useradd -u 1000 -g 1000 -m -s /bin/bash "${USERNAME}"; \
    fi && \
    echo "${USERNAME} ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers.d/010-${USERNAME} && \
    chmod 0440 /etc/sudoers.d/010-${USERNAME}

# tcpdump needs raw sockets to capture on davrosnet
RUN setcap cap_net_raw,cap_net_admin+eip /usr/bin/tcpdump || true

# Let the attacker read captures
RUN usermod -aG wireshark "${USERNAME}" 2>/dev/null || true

# The target runs ROS as uid/gid 1500 and leaves the keystore 0750, so the
# read-only mount at /target-keystore is group-readable and nothing else.
RUN groupadd -g 1500 rostarget 2>/dev/null || true; \
    usermod -aG rostarget "${USERNAME}" 2>/dev/null || true

# ROS on every shell, and uv's tooling on PATH.
RUN printf '%s\n' \
        'source /opt/ros/jazzy/setup.bash' \
        'export PATH="$HOME/.local/bin:$PATH"' \
        'export RMW_IMPLEMENTATION=rmw_fastrtps_cpp' \
        '# The attacker must never inherit the target'\''s security posture.' \
        'unset ROS_SECURITY_ENABLE ROS_SECURITY_STRATEGY ROS_SECURITY_KEYSTORE ROS_SECURITY_ENCLAVE_OVERRIDE' \
        > /etc/profile.d/99-attacker-env.sh && \
    cat /etc/profile.d/99-attacker-env.sh >> /home/${USERNAME}/.bashrc && \
    chown ${USERNAME}:${USERNAME} /home/${USERNAME}/.bashrc

# uv writes its cache and venvs somewhere predictable and writable.
ENV UV_LINK_MODE=copy \
    UV_CACHE_DIR=/home/${USERNAME}/.cache/uv \
    RMW_IMPLEMENTATION=rmw_fastrtps_cpp

USER ${USERNAME}
WORKDIR /workspace
CMD ["sleep", "infinity"]

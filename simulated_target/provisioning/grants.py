from pydantic import BaseModel, Field

from ..robot import graph_spec


class Grant(BaseModel):
    """A node's actual topic usage, as the provisioner needs it."""
    enclave: str
    node: str
    publish: list[str] = Field(default_factory=list)
    subscribe: list[str] = Field(default_factory=list)
    reply: list[str] = Field(default_factory=list)
    request: list[str] = Field(default_factory=list)

    @classmethod
    def from_spec(cls, spec: graph_spec.NodeSpec) -> "Grant":
        return cls(
            enclave=spec.enclave, node=spec.name,
            publish=list(spec.publishes),
            subscribe=list(spec.subscribes),
            reply=list(spec.replies),
        )


GRAPH: list[Grant] = [Grant.from_spec(spec) for spec in graph_spec.NODES]

# Enumerated, not "*": a wildcard here would be an A.3.10 finding of its own.
ROSAPI_SERVICES: tuple[str, ...] = (
    "~/action_feedback_details", "~/action_goal_details",
    "~/action_result_details", "~/action_servers", "~/action_type",
    "~/delete_param", "~/get_param", "~/get_param_names", "~/get_ros_version",
    "~/get_time", "~/has_param", "~/interfaces", "~/message_details",
    "~/node_details", "~/nodes", "~/publishers", "~/service_node",
    "~/service_providers", "~/service_request_details",
    "~/service_response_details", "~/service_type", "~/services",
    "~/services_for_type", "~/set_param", "~/subscribers", "~/topic_type",
    "~/topics", "~/topics_and_raw_types", "~/topics_for_type",
)

# Its client manager publishes these, and dies without them.
BRIDGE_STATUS_TOPICS: tuple[str, ...] = ("client_count", "connected_clients")


def bridge_grants(enclave: str) -> list[Grant]:
    """B.0.2. What the bridge's two nodes hold inside the enclave they borrow."""
    topics = [topic.name for topic in graph_spec.TOPICS]
    return [
        Grant(
            enclave=enclave, node="rosbridge_websocket",
            publish=topics + list(BRIDGE_STATUS_TOPICS),
            subscribe=list(topics),
            request=[f"/rosapi/{name.removeprefix('~/')}" for name in ROSAPI_SERVICES],
        ),
        Grant(enclave=enclave, node="rosapi", reply=list(ROSAPI_SERVICES)),
    ]


def unique_enclaves(grants: list[Grant]) -> list[str]:
    """Enclave paths in order, deduplicated: more than one node can share one."""
    ordered: list[str] = []
    for grant in grants:
        if grant.enclave not in ordered:
            ordered.append(grant.enclave)
    return ordered

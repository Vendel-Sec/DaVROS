from pathlib import Path
from xml.etree import ElementTree as ET

from .grants import Grant, unique_enclaves
from .xml_utils import write_xml

# What sros2's own reference policy grants every node, from
# test/policies/common/node/{logging,time,parameters,types}.xml. Without these a
# node cannot create its rosout publisher and never reaches its own topics.
COMMON_PUBLISH = ("rosout",)
COMMON_SUBSCRIBE = ("/clock",)
COMMON_PUBSUB = ("/parameter_events",)
COMMON_SERVICES = (
    "~/describe_parameters", "~/get_parameter_types", "~/get_parameters",
    "~/get_type_description", "~/list_parameters", "~/set_parameters",
    "~/set_parameters_atomically",
)


def write_policy(path: Path, grants: list[Grant]) -> None:
    """An sros2 policy document, the input to `ros2 security create_permission`."""
    policy = ET.Element("policy", {"version": "0.2.0"})
    enclaves = ET.SubElement(policy, "enclaves")
    # Grouped: sros2 reads only the first <enclave> element for a given path.
    for enclave in unique_enclaves(grants):
        enc = ET.SubElement(enclaves, "enclave", {"path": enclave})
        profiles = ET.SubElement(enc, "profiles")
        for grant in (item for item in grants if item.enclave == enclave):
            prof = ET.SubElement(
                profiles, "profile", {"ns": "/", "node": grant.node})
            publish = set(grant.publish) | set(COMMON_PUBLISH)
            subscribe = set(grant.subscribe) | set(COMMON_SUBSCRIBE)
            for verb, topics in (("publish", publish), ("subscribe", subscribe)):
                if not topics:
                    continue
                tl = ET.SubElement(prof, "topics", {verb: "ALLOW"})
                for t in sorted(topics):
                    ET.SubElement(tl, "topic").text = t
            pubsub = ET.SubElement(
                prof, "topics", {"publish": "ALLOW", "subscribe": "ALLOW"})
            for t in COMMON_PUBSUB:
                ET.SubElement(pubsub, "topic").text = t
            common = ET.SubElement(
                prof, "services", {"reply": "ALLOW", "request": "ALLOW"})
            for name in COMMON_SERVICES:
                ET.SubElement(common, "service").text = name
            for verb, services in (("reply", grant.reply), ("request", grant.request)):
                if not services:
                    continue
                sl = ET.SubElement(prof, "services", {verb: "ALLOW"})
                for name in sorted(services):
                    ET.SubElement(sl, "service").text = name
    write_xml(policy, path)

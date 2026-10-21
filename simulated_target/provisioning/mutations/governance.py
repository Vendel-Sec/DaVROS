# Every mutation takes (posture, keystore, grants) so the registry drives them uniformly.

from xml.etree import ElementTree as ET

from ..grants import Grant
from ..keystore import Keystore, smime_sign
from ..posture import Posture
from ..xml_utils import read_signed_xml, set_text, write_xml


def _append_topic_rule(
    rules: ET.Element, expression: str, posture: Posture, *, permissive: bool,
) -> None:
    """One <topic_rule>. `permissive` is the A.3.8 wildcard, which turns off every
    per-topic control whatever the rest of the posture asks for."""
    oa = posture.origin_auth
    tr = ET.SubElement(rules, "topic_rule")
    ET.SubElement(tr, "topic_expression").text = expression
    ET.SubElement(tr, "enable_discovery_protection").text = (
        "false" if permissive or not posture.topic_discovery_protection
        else "true")                                                 # A.3.6
    ET.SubElement(tr, "enable_liveliness_protection").text = (
        "false" if permissive or not posture.topic_liveliness_protection
        else "true")                                                 # A.3.7
    ET.SubElement(tr, "enable_read_access_control").text = (
        "false" if permissive or not posture.read_ac else "true")    # A.3.4
    ET.SubElement(tr, "enable_write_access_control").text = (
        "false" if permissive or not posture.write_ac else "true")   # A.3.5
    ET.SubElement(tr, "metadata_protection_kind").text = (
        posture.metadata_protection.with_origin_auth(oa))            # A.2.5
    # No origin-authentication variant exists for payload protection.
    ET.SubElement(tr, "data_protection_kind").text = (
        posture.data_protection.value)                               # A.2.6, A.2.7


def mutate_governance(posture: Posture, ks: Keystore, grants: list[Grant]) -> str:  # noqa: ARG001
    """Rewrite the domain rule and the topic rules of the signed governance document"""
    docs = ks.governance_docs()
    if not docs:
        raise SystemExit("no governance.p7s in the baseline keystore")

    oa = posture.origin_auth
    changed: list[str] = []

    for p7s in docs:
        root = read_signed_xml(p7s)
        rule = root.find("./domain_access_rules/domain_rule")
        if rule is None:
            raise SystemExit(f"unexpected governance shape in {p7s}")

        # A.3.9, scope the rule to the operational domain or to a broad range.
        domains = rule.find("domains")
        if domains is not None:
            for child in list(domains):
                domains.remove(child)
            if posture.domains_range:
                lo, _, hi = posture.domains_range.partition("-")
                rng = ET.SubElement(domains, "id_range")
                ET.SubElement(rng, "min").text = lo or "0"
                ET.SubElement(rng, "max").text = hi or lo or "0"
            else:
                ET.SubElement(domains, "id").text = str(posture.domain_id)

        set_text(rule, "allow_unauthenticated_participants",
                 "true" if posture.allow_unauthenticated else "false")   # A.3.2
        set_text(rule, "enable_join_access_control",
                 "true" if posture.join_ac else "false")                 # A.3.3
        set_text(rule, "discovery_protection_kind",
                 posture.discovery_protection.with_origin_auth(oa))      # A.2.3
        set_text(rule, "liveliness_protection_kind",
                 posture.liveliness_protection.with_origin_auth(oa))     # A.2.4
        set_text(rule, "rtps_protection_kind",
                 posture.rtps_protection.with_origin_auth(oa))           # A.2.2

        tars = rule.find("topic_access_rules")
        if tars is None:
            tars = ET.SubElement(rule, "topic_access_rules")
        for child in list(tars):
            tars.remove(child)

        # A.3.8, first-match semantics. A permissive "*" placed first shadows
        # every specific rule below it. Placed last it is a restrictive fallback.
        if posture.wildcard_first:
            _append_topic_rule(tars, "*", posture, permissive=True)
        for topic in ("rt/cmd_vel", "rt/goal_pose", "rt/scan", "rt/odom"):
            _append_topic_rule(tars, topic, posture, permissive=False)
        if not posture.wildcard_first:
            _append_topic_rule(tars, "*", posture, permissive=False)

        staged = p7s.with_suffix(".xml")
        write_xml(root, staged)
        smime_sign(staged, p7s, ks, posture.sign_governance, "A.3.16")
        changed.append(str(p7s.relative_to(ks.root)))

    return (f"{len(changed)} governance document(s), "
            f"rtps={posture.rtps_protection.with_origin_auth(oa)} "
            f"data={posture.data_protection.value} "
            f"unauth={posture.allow_unauthenticated} "
            f"read_ac={posture.read_ac} write_ac={posture.write_ac} "
            f"signed={posture.sign_governance}")

# Uniform mutation signature; datetime.UTC is 3.11+, Humble ships 3.10.

import datetime as dt
from xml.etree import ElementTree as ET

from ..grants import Grant
from ..keystore import Keystore, smime_sign
from ..posture import Posture
from ..xml_utils import read_signed_xml, set_text, write_xml


def mutate_permissions(posture: Posture, ks: Keystore, grants: list[Grant]) -> str:  # noqa: ARG001
    """Edit the signed permissions document sros2 produced, then re-sign. These are"""
    touched = 0
    for ed in ks.enclave_dirs():
        p7s = ed / "permissions.p7s"
        if not p7s.exists():
            continue
        root = read_signed_xml(p7s)
        for g in root.findall("./permissions/grant"):
            # A.3.13, a wildcard subject name makes the grant apply to whichever
            # process holds the key rather than to the node it was issued for.
            if posture.subject_wildcard:
                set_text(g, "subject_name", "*")

            # A.3.12, an unbounded not_after means a decommissioned enclave stays
            # authorised forever.
            validity = g.find("validity")
            if validity is not None:
                not_after = (
                    dt.datetime.now(dt.timezone.utc)  # noqa: UP017
                    + dt.timedelta(days=posture.perms_days)
                )
                set_text(validity, "not_after", not_after.strftime("%Y-%m-%dT%H:%M:%S"))

            # A.3.8, first-match semantics: a permissive "*" above the real
            # per-topic rules leaves them in the file and unreachable.
            catch_all = None
            if posture.wildcard_first:
                catch_all = ET.Element("allow_rule")
                domains = ET.SubElement(catch_all, "domains")
                ET.SubElement(domains, "id").text = str(posture.domain_id)
                for verb in ("publish", "subscribe"):
                    tl = ET.SubElement(ET.SubElement(catch_all, verb), "topics")
                    ET.SubElement(tl, "topic").text = "*"
                kids = list(g)
                at = next(
                    (i for i, k in enumerate(kids) if k.tag == "allow_rule"), len(kids)
                )
                g.insert(at, catch_all)

            for allow in g.findall("allow_rule"):
                if allow is catch_all:
                    continue
                # A.3.9, the grant's own domain scope.
                scope = allow.find("domains")
                if scope is not None and posture.domains_range:
                    for child in list(scope):
                        scope.remove(child)
                    lo, _, hi = posture.domains_range.partition("-")
                    rng = ET.SubElement(scope, "id_range")
                    ET.SubElement(rng, "min").text = lo or "0"
                    ET.SubElement(rng, "max").text = hi or lo or "0"

                # A.3.14, a relay grant is a bridge and replay position inside
                # the domain for traffic the participant neither pubs nor subs.
                if posture.relay_grant and allow.find("relay") is None:
                    relay = ET.SubElement(allow, "relay")
                    tl = ET.SubElement(relay, "topics")
                    ET.SubElement(tl, "topic").text = "*"

            # A.3.11, the specification's implied default with no <default>
            # element is DENY. ALLOW fails open, so topics added later are
            # automatically world-writable.
            set_text(g, "default", posture.perms_default)

        staged = ed / "permissions.mutated.xml"
        write_xml(root, staged)
        smime_sign(staged, p7s, ks, posture.sign_permissions, "A.3.17")
        staged.unlink(missing_ok=True)
        touched += 1

    return (f"{touched} permissions document(s), wildcard_first={posture.wildcard_first} "
            f"default={posture.perms_default} subject_wildcard={posture.subject_wildcard} "
            f"relay={posture.relay_grant} validity_days={posture.perms_days} "
            f"signed={posture.sign_permissions}")

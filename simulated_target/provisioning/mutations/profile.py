# Every mutation takes (posture, keystore, grants) so the registry drives them uniformly.

import shutil
from pathlib import Path
from xml.etree import ElementTree as ET

from ..grants import Grant
from ..keystore import Keystore
from ..posture import Posture
from ..process import chmod, run
from ..xml_utils import write_xml
from .zenoh import mutate_zenoh_configs


def _write_empty_crl(ks: Keystore, dirs: list[Path]) -> None:
    """A.1.6. An empty but valid CRL, so identity_crl can point at something real."""
    work = ks.root / ".work"
    work.mkdir(exist_ok=True)
    (work / "index.txt").write_text("")
    (work / "crlnumber").write_text("01\n")
    conf = work / "crl.cnf"
    conf.write_text(
        "[ ca ]\ndefault_ca = CA_default\n\n[ CA_default ]\n"
        f"database = {work / 'index.txt'}\n"
        f"crlnumber = {work / 'crlnumber'}\n"
        f"certificate = {ks.identity_ca_cert}\n"
        f"private_key = {ks.identity_ca_key}\n"
        "default_md = sha256\ndefault_crl_days = 30\n"
    )
    crl = work / "identity_crl.pem"
    run("openssl", "ca", "-config", str(conf), "-gencrl", "-out", str(crl), quiet=True)
    for ed in dirs:
        shutil.copy2(crl, ed / "identity_crl.pem")


def _security_properties(
    posture: Posture, ed: Path, crl_written: bool,
) -> list[tuple[str, str]]:
    """The DDS-Security plugin properties for one enclave, in the order Fast DDS
    reads them. A.0.5, A.1.1, A.2.1 and A.3.1 are all "this list is absent"."""
    props = [
        ("dds.sec.auth.plugin", "builtin.PKI-DH"),
        ("dds.sec.auth.builtin.PKI-DH.identity_ca",
         f"file://{ed}/identity_ca.cert.pem"),
        ("dds.sec.auth.builtin.PKI-DH.identity_certificate",
         f"file://{ed}/cert.pem"),
        ("dds.sec.auth.builtin.PKI-DH.private_key", f"file://{ed}/key.pem"),
    ]
    if posture.key_passphrase:
        props.append(
            ("dds.sec.auth.builtin.PKI-DH.password", posture.key_passphrase))
    if crl_written:                                                  # A.1.6
        props.append(("dds.sec.auth.builtin.PKI-DH.identity_crl",
                      f"file://{ed}/identity_crl.pem"))
    props += [
        ("dds.sec.auth.builtin.PKI-DH.preferred_key_agreement",
         posture.key_agreement),                                     # A.1.7
        ("dds.sec.auth.builtin.PKI-DH.transmit_algorithms_as_legacy",
         "true" if posture.legacy_algorithms else "false"),          # A.1.8
        ("dds.sec.crypto.plugin", "builtin.AES-GCM-GMAC"),
        ("dds.sec.access.plugin", "builtin.Access-Permissions"),
        ("dds.sec.access.builtin.Access-Permissions.permissions_ca",
         f"file://{ed}/permissions_ca.cert.pem"),
        ("dds.sec.access.builtin.Access-Permissions.governance",
         f"file://{ed}/governance.p7s"),
        ("dds.sec.access.builtin.Access-Permissions.permissions",
         f"file://{ed}/permissions.p7s"),
    ]
    return props


def _fastdds_profile(posture: Posture, ed: Path, crl_written: bool) -> ET.Element:
    profiles = ET.Element(
        "profiles",
        {"xmlns": "http://www.eprosima.com/XMLSchemas/fastRTPS_Profiles"},
    )
    part = ET.SubElement(profiles, "participant",
                         {"profile_name": "target", "is_default_profile": "true"})
    rtps = ET.SubElement(part, "rtps")

    if posture.initial_peer:
        builtin = ET.SubElement(rtps, "builtin")
        peers = ET.SubElement(builtin, "initialPeersList")
        loc = ET.SubElement(peers, "locator")
        udp = ET.SubElement(loc, "udpv4")
        ET.SubElement(udp, "address").text = posture.initial_peer

    props_list = ET.SubElement(ET.SubElement(rtps, "propertiesPolicy"), "properties")
    if not posture.omit_plugins:
        for name, value in _security_properties(posture, ed, crl_written):
            element = ET.SubElement(props_list, "property")
            ET.SubElement(element, "name").text = name
            ET.SubElement(element, "value").text = value
    return profiles


# Cyclone's builtin plugins, with the entry points its config reference names.
CYCLONE_LIBRARIES = {
    "Authentication": ("dds_security_auth", "authentication"),
    "AccessControl": ("dds_security_ac", "access_control"),
    "Cryptographic": ("dds_security_crypto", "crypto"),
}


def _cyclone_library(parent: ET.Element) -> None:
    path, suffix = CYCLONE_LIBRARIES[parent.tag]
    ET.SubElement(parent, "Library", {
        "path": path,
        "initFunction": f"init_{suffix}",
        "finalizeFunction": f"finalize_{suffix}",
    })


def _cyclone_config(posture: Posture, ed: Path, _crl_written: bool) -> ET.Element:
    """The same posture as _fastdds_profile, minus A.1.7 and A.1.8, which Cyclone lacks."""
    root = ET.Element("CycloneDDS", {"xmlns": "https://cdds.io/config"})
    domain = ET.SubElement(root, "Domain", {"id": "any"})

    if posture.initial_peer:
        peers = ET.SubElement(ET.SubElement(domain, "Discovery"), "Peers")
        ET.SubElement(peers, "Peer", {"address": posture.initial_peer})

    if posture.omit_plugins:
        return root

    security = ET.SubElement(domain, "Security")
    auth = ET.SubElement(security, "Authentication")
    _cyclone_library(auth)
    ET.SubElement(auth, "IdentityCA").text = f"file:{ed}/identity_ca.cert.pem"
    ET.SubElement(auth, "IdentityCertificate").text = f"file:{ed}/cert.pem"
    ET.SubElement(auth, "PrivateKey").text = f"file:{ed}/key.pem"
    if posture.key_passphrase:
        ET.SubElement(auth, "Password").text = posture.key_passphrase

    access = ET.SubElement(security, "AccessControl")
    _cyclone_library(access)
    ET.SubElement(access, "PermissionsCA").text = f"file:{ed}/permissions_ca.cert.pem"
    ET.SubElement(access, "Governance").text = f"file:{ed}/governance.p7s"
    ET.SubElement(access, "Permissions").text = f"file:{ed}/permissions.p7s"

    _cyclone_library(ET.SubElement(security, "Cryptographic"))
    return root


def mutate_xml_profile(posture: Posture, ks: Keystore, grants: list[Grant]) -> str:  # noqa: ARG001
    """The rmw participant profile. sros2 does not generate one at all, which"""
    if posture.zenoh:
        return mutate_zenoh_configs(posture, ks)
    dirs = ks.enclave_dirs()
    if not dirs:
        return "no enclaves"

    crl_written = False
    if posture.crl and not posture.cyclone:
        _write_empty_crl(ks, dirs)
        crl_written = True

    build = _cyclone_config if posture.cyclone else _fastdds_profile
    for ed in dirs:
        write_xml(build(posture, ed, crl_written), ed / posture.profile_name)

    # A.4.1, a profile the ROS user can write is a profile that can be repointed
    # at an attacker's CA, and the change survives reboot.
    top = ks.root / posture.profile_name
    shutil.copy2(dirs[0] / posture.profile_name, top)
    chmod(top, 0o666 if posture.profile_writable else 0o444)

    plugins = "omitted" if posture.omit_plugins else "present"
    tuning = (
        "key_agreement and legacy_algorithms not applicable"
        if posture.cyclone else
        f"key_agreement={posture.key_agreement}, "
        f"legacy_algorithms={posture.legacy_algorithms}"
    )
    return (f"{posture.profile_name}: plugins {plugins}, "
            f"crl={'yes' if crl_written else 'no'}, {tuning}, "
            f"profile mode={'0666 WRITABLE' if posture.profile_writable else '0444'}")

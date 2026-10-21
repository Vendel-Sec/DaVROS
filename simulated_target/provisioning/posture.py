# ROS Humble ships Python 3.10, where enum.StrEnum does not exist yet.

from enum import Enum
from pathlib import Path
from typing import Literal

from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class ProtectionKind(str, Enum):  # noqa: UP042
    NONE = "NONE"
    SIGN = "SIGN"
    ENCRYPT = "ENCRYPT"

    def with_origin_auth(self, enabled: bool) -> str:
        """Leaf A.2.8. Origin authentication binds a message to the sending"""
        if not enabled or self is ProtectionKind.NONE:
            return self.value
        return f"{self.value}_WITH_ORIGIN_AUTHENTICATION"


class KeyType(str, Enum):  # noqa: UP042
    EC = "ec"
    RSA = "rsa"


class Posture(BaseSettings):
    """One field per leaf of ros2_attack_tree.md, read from TARGET_* env vars."""
    model_config = SettingsConfigDict(
        env_prefix="TARGET_", case_sensitive=False, extra="ignore",
    )

    # --- A.0, is the security layer in force ------------------------------ #
    security_enable: str = "true"                        # A.0.1
    security_strategy: str = "Enforce"                   # A.0.2
    domain_id: int = 42                                  # A.0.6, 0 is the default
    enclave_override: str = ""                           # A.0.4
    keystore_mode: str = "0750"                           # A.0.3, A.4.2
    omit_plugins: bool = False                           # A.0.5, A.1.1, A.2.1, A.3.1
    zenoh_mtls: bool = True                              # A.1.1, Zenoh only

    # --- A.1, authentication ---------------------------------------------- #
    shared_identity: bool = False                        # A.1.3
    key_mode: str = "0400"                                # A.1.4
    key_passphrase: str = ""                             # A.1.5
    leak_passphrase: bool = False                        # A.1.5
    crl: bool = True                                     # A.1.6
    key_agreement: str = "AUTO"                          # A.1.7
    legacy_algorithms: bool = False                      # A.1.8
    cert_days: int = 365                                 # A.1.9
    key_type: KeyType = KeyType.EC                       # A.1.10
    key_bits: int = 2048                                 # A.1.10, RSA only

    # --- A.2, crypto on the wire ------------------------------------------ #
    rtps_protection: ProtectionKind = ProtectionKind.ENCRYPT        # A.2.2
    discovery_protection: ProtectionKind = ProtectionKind.ENCRYPT   # A.2.3
    liveliness_protection: ProtectionKind = ProtectionKind.ENCRYPT  # A.2.4
    metadata_protection: ProtectionKind = ProtectionKind.ENCRYPT    # A.2.5
    data_protection: ProtectionKind = ProtectionKind.ENCRYPT        # A.2.6, A.2.7
    origin_auth: bool = True                                        # A.2.8

    # --- A.3, access control ----------------------------------------------- #
    allow_unauthenticated: bool = False                  # A.3.2
    join_ac: bool = True                                 # A.3.3
    read_ac: bool = True                                 # A.3.4
    write_ac: bool = True                                # A.3.5
    topic_discovery_protection: bool = True              # A.3.6
    topic_liveliness_protection: bool = True             # A.3.7
    wildcard_first: bool = False                         # A.3.8, A.3.10
    domains_range: str = ""                              # A.3.9, e.g. "0-230"
    perms_default: Literal["ALLOW", "DENY"] = "DENY"     # A.3.11
    perms_days: int = 365                                # A.3.12
    subject_wildcard: bool = False                       # A.3.13
    shared_enclave: bool = False                         # A.3.13
    relay_grant: bool = False                            # A.3.14
    separate_ca: bool = True                             # A.3.15, hardening direction
    sign_governance: bool = True                         # A.3.16
    sign_permissions: bool = True                        # A.3.17

    # --- A.4, artefact delivery -------------------------------------------- #
    strip_ca_key: bool = True                            # A.4.3, hardening direction
    profile_writable: bool = False                       # A.4.1

    # --- B, host and exposed services ------------------------------------- #
    rosbridge: bool = False                              # B.0.2
    rosbridge_enclave: str = "/mission_planner"          # B.0.2

    # --- plumbing ---------------------------------------------------------- #
    # Decides the profile format. A.1.7 and A.1.8 do nothing on Cyclone.
    rmw: Literal["rmw_fastrtps_cpp", "rmw_cyclonedds_cpp", "rmw_zenoh_cpp"] = "rmw_fastrtps_cpp"
    keystore: Path = Path("/keystore")
    initial_peer: str = ""
    reprovision: bool = False

    @field_validator("keystore_mode", "key_mode")
    @classmethod
    def _octal(cls, v: str) -> str:
        int(v, 8)  # raises on a non-octal string, which is the point
        return v

    @property
    def cyclone(self) -> bool:
        return self.rmw == "rmw_cyclonedds_cpp"

    @property
    def zenoh(self) -> bool:
        return self.rmw == "rmw_zenoh_cpp"

    @property
    def profile_name(self) -> str:
        """The rmw profile's filename, in every enclave and at the keystore root."""
        if self.zenoh:
            return "zenoh_session.json5"
        return "cyclonedds.xml" if self.cyclone else "fastdds_profile.xml"

    @property
    def mode_keystore(self) -> int:
        return int(self.keystore_mode, 8)

    @property
    def mode_key(self) -> int:
        return int(self.key_mode, 8)

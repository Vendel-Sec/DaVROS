from pathlib import Path

from .process import run


class Keystore:
    """Paths inside an sros2 keystore, tolerant of both CA naming conventions."""

    def __init__(self, root: Path) -> None:
        self.root = root
        self.public = root / "public"
        self.private = root / "private"
        self.enclaves = root / "enclaves"

    def _first(self, base: Path, *names: str) -> Path:
        for n in names:
            p = base / n
            if p.exists():
                return p
        return base / names[0]

    @property
    def identity_ca_cert(self) -> Path:
        return self._first(self.public, "identity_ca.cert.pem", "ca.cert.pem")

    @property
    def identity_ca_key(self) -> Path:
        return self._first(self.private, "identity_ca.key.pem", "ca.key.pem")

    @property
    def permissions_ca_cert(self) -> Path:
        return self._first(self.public, "permissions_ca.cert.pem", "ca.cert.pem")

    @property
    def permissions_ca_key(self) -> Path:
        return self._first(self.private, "permissions_ca.key.pem", "ca.key.pem")

    def enclave_dirs(self) -> list[Path]:
        if not self.enclaves.is_dir():
            return []
        return sorted(
            d for d in self.enclaves.rglob("*")
            if d.is_dir() and (d / "cert.pem").exists()
        )

    def governance_docs(self) -> list[Path]:
        return sorted(self.enclaves.rglob("governance.p7s"))


def smime_sign(xml: Path, out: Path, ks: Keystore, sign: bool, leaf: str) -> None:
    """Sign with the keystore's own Permissions CA, the way sros2 does, or write the"""
    if not sign:
        out.write_bytes(
            f"# UNSIGNED. No S/MIME signature binds this document to the "
            f"Permissions CA. Leaf {leaf}.\n".encode()
            + xml.read_bytes()
        )
        return
    key = ks.permissions_ca_key
    if not key.exists():
        raise SystemExit(
            f"cannot re-sign {out.name}: no Permissions CA key at {key}. "
            "A mutation that rewrites a signed document must run before "
            "strip_ca_key removes private/."
        )
    # Default outform is SMIME, which keeps the XML in cleartext next to the
    # signature. -outform PEM would emit an opaque PKCS7 blob that neither
    # read_signed_xml nor Fast DDS can read the <dds> document out of.
    run("openssl", "smime", "-sign", "-in", str(xml), "-text", "-out", str(out),
        "-signer", str(ks.permissions_ca_cert), "-inkey", str(key),
        "-nodetach", quiet=True)

import subprocess
from pathlib import Path
from xml.etree import ElementTree as ET


def _dds_element(text: str) -> ET.Element | None:
    start = text.find("<dds")
    end = text.rfind("</dds>")
    if start < 0 or end < 0:
        return None
    return ET.fromstring(text[start:end + len("</dds>")])


def read_signed_xml(path: Path) -> ET.Element:
    """Pull the XML document out of a .p7s, opaque or cleartext, or a plain .xml."""
    text = path.read_text(encoding="utf-8", errors="replace")
    found = _dds_element(text)
    if found is not None:
        return found

    # sros2 signs governance and permissions as opaque S/MIME (smime-type=
    # signed-data), so the document is base64 inside the PKCS7 rather than
    # beside it. Unwrap it. -noverify because the point here is to read the
    # content, not to decide the signature: A.3.16 and A.3.17 do that.
    inform = "PEM" if "BEGIN PKCS7" in text else "SMIME"
    proc = subprocess.run(
        ["openssl", "smime", "-verify", "-noverify", "-inform", inform,
         "-in", str(path)],
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, check=False, text=True,
    )
    if proc.returncode == 0:
        found = _dds_element(proc.stdout)
        if found is not None:
            return found
    raise SystemExit(f"no <dds> document found in {path}")


def write_xml(el: ET.Element, path: Path) -> None:
    ET.indent(el, space="  ")
    path.write_bytes(
        b'<?xml version="1.0" encoding="UTF-8"?>\n' + ET.tostring(el, encoding="utf-8")
    )


def set_text(parent: ET.Element, tag: str, value: str) -> None:
    """Set an existing element's text, or append it if the baseline omitted it."""
    el = parent.find(tag)
    if el is None:
        el = ET.SubElement(parent, tag)
    el.text = value

#!/usr/bin/env python3
"""Web UI for the simulated target's posture.

Writes simulated_target/posture/preset.env, the overlay docker-compose.yml loads
over the hardened target.env, and can recreate the target so it takes effect.
The form is built from target.env itself: its comments give each knob its help
text, its leaves and its section, so a knob added there shows up here.

    ./configurator.py                                    # http://127.0.0.1:8765
    ./configurator.py --port 9000                        # another port

Standard library only, so it runs from the host's system Python with nothing
installed.
"""

from __future__ import annotations

import argparse
import contextlib
import json
import re
import subprocess
import threading
import time
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

WORKSPACE = Path(__file__).resolve().parent
POSTURE = WORKSPACE / "simulated_target" / "posture"
BASELINE = POSTURE / "target.env"
OVERLAY = POSTURE / "preset.env"
PRESETS = POSTURE / "presets"
PAGE = POSTURE / "configurator.html"
# The peer reads the keystore once, at start, and a recreated target
# reprovisions it, so the peer is recreated too. Compose only acts on the
# services it is given, never on their dependents.
RECREATE = [
    "docker", "compose", "-f", "docker-compose.yml",
    "up", "-d", "--force-recreate", "--wait", "target", "peer",
]

PROTECTION = ["NONE", "SIGN", "ENCRYPT"]
# Knobs with a closed set of values, rendered as radio buttons. true/false knobs
# become switches without being listed.
CHOICES = {
    "TARGET_SECURITY_STRATEGY": ["Enforce", "Permissive"],
    "TARGET_KEY_AGREEMENT": ["AUTO", "ECDH", "DH", "DH+MODP-2048-256"],
    "TARGET_KEY_TYPE": ["ec", "rsa"],
    "TARGET_KEY_BITS": ["1024", "2048", "3072", "4096"],
    "TARGET_RTPS_PROTECTION": PROTECTION,
    "TARGET_DISCOVERY_PROTECTION": PROTECTION,
    "TARGET_LIVELINESS_PROTECTION": PROTECTION,
    "TARGET_METADATA_PROTECTION": PROTECTION,
    "TARGET_DATA_PROTECTION": PROTECTION,
    "TARGET_PERMS_DEFAULT": ["DENY", "ALLOW"],
}
# A knob that only means something while another one has a given value.
ONLY_WHEN = {
    "TARGET_KEY_BITS": ("TARGET_KEY_TYPE", "rsa"),
    "TARGET_ROSBRIDGE_ENCLAVE": ("TARGET_ROSBRIDGE", "true"),
}

ASSIGN = re.compile(r"^([A-Z][A-Z0-9_]*)=(.*)$")
LEAF = re.compile(r"\b[AB]\.\d+(?:\.\d+)?\b")
LEADING_LEAVES = re.compile(r"^(?:[AB]\.[\d.]+|and|,|\s)+")
# Compose reads env files unquoted, so anything that needs quoting is refused
# rather than written in a form it would misread.
SAFE_VALUE = re.compile(r"^[A-Za-z0-9_./,+:@*-]*$")
LOCAL_HOSTS = {"localhost", "127.0.0.1", "[::1]"}

recreating = threading.Lock()


def read_assignments(path: Path) -> tuple[dict[str, str], list[str]]:
    """KEY=VALUE pairs of an env file, and the comment block before the first."""
    values: dict[str, str] = {}
    preamble: list[str] = []
    for raw in path.read_text().splitlines():
        line = raw.strip()
        if m := ASSIGN.match(line):
            values[m[1]] = m[2]
        elif line.startswith("#") and not values:
            preamble.append(line.lstrip("#").strip())
    return values, preamble


def read_baseline() -> list[dict[str, Any]]:
    knobs: list[dict[str, Any]] = []
    section, comment = "General", list[str]()
    for raw in BASELINE.read_text().splitlines():
        line = raw.strip()
        if not line:
            comment = []
        elif line.startswith("# ---"):
            section, comment = line.strip("#- "), []
        elif line.startswith("#"):
            comment.append(line.lstrip("#").strip())
        elif m := ASSIGN.match(line):
            name, value = m[1], m[2]
            text = " ".join(comment)
            if name in CHOICES:
                kind = "radio"
            elif value in ("true", "false"):
                kind = "switch"
            elif name.endswith("_MODE"):
                kind = "octal"
            elif value.isdigit():
                kind = "int"
            else:
                kind = "text"
            knobs.append({
                "name": name,
                "label": name.removeprefix("TARGET_").replace("_", " ").capitalize(),
                "section": section,
                "leaves": list(dict.fromkeys(LEAF.findall(text))),
                "help": LEADING_LEAVES.sub("", text),
                "kind": kind,
                "options": CHOICES.get(name, []),
                "onlyWhen": ONLY_WHEN.get(name),
                "baseline": value,
            })
            comment = []
    return knobs


def read_presets() -> list[dict[str, Any]]:
    presets = []
    for path in sorted(PRESETS.glob("*.env")):
        values, preamble = read_assignments(path)
        presets.append({
            "name": path.stem,
            "description": " ".join(preamble),
            "values": values,
        })
    return presets


def state() -> dict[str, Any]:
    knobs = read_baseline()
    overlay = read_assignments(OVERLAY)[0] if OVERLAY.exists() else {}
    known = {k["name"] for k in knobs}
    for knob in knobs:
        knob["value"] = overlay.get(knob["name"], knob["baseline"])
    return {
        "knobs": knobs,
        "presets": read_presets(),
        "overlay": OVERLAY.exists(),
        "extra": {k: v for k, v in overlay.items() if k not in known},
        "recreateCommand": " ".join(RECREATE),
    }


def validate(knobs: list[dict[str, Any]], values: dict[str, Any]) -> dict[str, str]:
    known = {k["name"]: k for k in knobs}
    if unknown := set(values) - set(known):
        raise ValueError(f"unknown knobs: {', '.join(sorted(unknown))}")
    clean = {}
    for name, knob in known.items():
        value = values.get(name, knob["baseline"])
        if not isinstance(value, str):
            raise ValueError(f"{name}: expected a string")
        if knob["kind"] == "radio" and value not in knob["options"]:
            raise ValueError(f"{name}: must be one of {', '.join(knob['options'])}")
        if knob["kind"] == "switch" and value not in ("true", "false"):
            raise ValueError(f"{name}: must be true or false")
        if knob["kind"] == "octal" and not re.fullmatch(r"0?[0-7]{3}", value):
            raise ValueError(f"{name}: must be an octal mode such as 0750")
        if knob["kind"] == "int" and not value.isdigit():
            raise ValueError(f"{name}: must be a non-negative integer")
        if not SAFE_VALUE.match(value):
            raise ValueError(f"{name}: only letters, digits and _ . / , + : @ * -")
        clean[name] = value
    return clean


def write_overlay(values: dict[str, str], preset: str | None) -> str:
    """Write preset.env, or remove it when nothing differs from the baseline."""
    knobs = read_baseline()
    values = validate(knobs, values)
    extra = state()["extra"]
    diff = {k["name"]: values[k["name"]] for k in knobs
            if values[k["name"]] != k["baseline"]}

    if not diff and not extra:
        OVERLAY.unlink(missing_ok=True)
        return "preset.env removed: the target runs the hardened baseline."

    # Unchanged from a preset: copy it, so its comments come along as with cp.
    if preset and (path := PRESETS / f"{preset}.env").is_file():
        expected = {k["name"]: k["baseline"] for k in knobs}
        expected.update(read_assignments(path)[0])
        if expected == values and not extra:
            OVERLAY.write_text(path.read_text())
            return f"preset.env is now the {preset} preset."

    lines = [
        "# Written by configurator.py. Loaded over",
        "# target.env, so only the knobs that differ from the hardened baseline",
        "# are listed.",
    ]
    if preset:
        lines.append(f"# Started from the {preset} preset.")
    lines += [f"{k}={v}" for k, v in diff.items()]
    if extra:
        lines.append("# Not in target.env, kept as found.")
        lines += [f"{k}={v}" for k, v in extra.items()]
    OVERLAY.write_text("\n".join(lines) + "\n")
    return f"preset.env written: {len(diff)} knob(s) differ from the baseline."


def report_error(what: str, detail: str = "") -> None:
    """Print a failure to stdout, so it outlives the browser tab that saw it."""
    print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] ERROR {what}", flush=True)
    for line in detail.splitlines():
        print(f"    {line}", flush=True)


def recreate_target() -> tuple[bool, str]:
    command = " ".join(RECREATE)
    if not recreating.acquire(blocking=False):
        report_error("recreate refused: another one is already running")
        return False, "A recreate is already running."
    try:
        run = subprocess.run(
            RECREATE, cwd=WORKSPACE, capture_output=True, text=True,
            timeout=600, check=False,
        )
    except FileNotFoundError:
        report_error("recreate failed: docker is not on PATH", command)
        return False, "docker is not on PATH. Run this where it is:\n" + command
    except subprocess.TimeoutExpired:
        report_error("recreate failed: no exit within 10 minutes", command)
        return False, "docker compose did not finish within 10 minutes."
    finally:
        recreating.release()
    output = (run.stdout + run.stderr).strip()
    if run.returncode != 0:
        report_error(f"recreate failed: exit {run.returncode}", f"{command}\n{output}")
    return run.returncode == 0, output


class Handler(BaseHTTPRequestHandler):
    allowed_hosts: set[str] = LOCAL_HOSTS

    def _host_ok(self) -> bool:
        # Refuses DNS rebinding: this server writes files and drives docker.
        host = (self.headers.get("Host") or "").rsplit(":", 1)[0]
        return host in self.allowed_hosts

    def _send(self, status: HTTPStatus, body: bytes, content_type: str) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        try:
            self.end_headers()
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            # The tab was closed or reloaded, or a proxy gave up, while a save
            # or recreate ran. The work is done; only its result is lost.
            report_error(
                f"browser disconnected before the response to {self.command} "
                f"{self.path} was sent",
                "whatever it asked for still happened: reload the page, and "
                "check docker ps if it was a recreate",
            )

    def _json(self, status: HTTPStatus, payload: dict[str, Any]) -> None:
        self._send(status, json.dumps(payload).encode(), "application/json")

    def do_GET(self) -> None:
        if not self._host_ok():
            self._json(HTTPStatus.FORBIDDEN, {"error": "unexpected Host header"})
        elif self.path == "/":
            self._send(HTTPStatus.OK, PAGE.read_bytes(), "text/html; charset=utf-8")
        elif self.path == "/api/state":
            self._json(HTTPStatus.OK, state())
        else:
            self._json(HTTPStatus.NOT_FOUND, {"error": "not found"})

    def do_POST(self) -> None:
        # A JSON body cannot be sent cross-origin without a preflight, which this
        # server never answers, so another site cannot post here.
        if not self._host_ok() or not (self.headers.get("Content-Type") or "").startswith(
            "application/json"
        ):
            self._json(HTTPStatus.FORBIDDEN, {"error": "refused"})
            return
        if self.path != "/api/apply":
            self._json(HTTPStatus.NOT_FOUND, {"error": "not found"})
            return
        try:
            body = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))))
            message = write_overlay(body.get("values", {}), body.get("preset"))
        except (ValueError, AttributeError) as exc:
            report_error("save refused", str(exc))
            self._json(HTTPStatus.BAD_REQUEST, {"error": str(exc)})
            return
        except OSError as exc:
            report_error("could not write preset.env", str(exc))
            self._json(HTTPStatus.INTERNAL_SERVER_ERROR, {"error": str(exc)})
            return
        ok, output = True, ""
        if body.get("recreate"):
            ok, output = recreate_target()
        self._json(HTTPStatus.OK, {
            "ok": ok, "message": message, "output": output, "state": state(),
        })

    def log_message(self, format: str, *args: Any) -> None:
        if self.command == "POST":
            super().log_message(format, *args)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--host", default="127.0.0.1",
                        help="address to bind (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--allow-host", action="append", default=[], metavar="NAME",
                        help="extra Host header to accept, e.g. a forwarded hostname")
    args = parser.parse_args()
    Handler.allowed_hosts = LOCAL_HOSTS | set(args.allow_host)
    server = ThreadingHTTPServer((args.host, args.port), Handler)
    print(f"DaVROS posture configurator on http://{args.host}:{args.port}")
    with contextlib.suppress(KeyboardInterrupt):
        server.serve_forever()


if __name__ == "__main__":
    main()

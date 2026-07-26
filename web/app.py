#!/usr/bin/env python3
"""Fleet control panel for device emulator and HMI subprocesses."""

from __future__ import annotations

import argparse
import fcntl
import json
import logging
import os
import re
import shutil
import signal
import socket
import sqlite3
import struct
import subprocess
import sys
import time
import uuid
from pathlib import Path
from typing import Any, Callable
from urllib.parse import urljoin, urlparse

from flask import Flask, flash, g, jsonify, redirect, render_template, request, url_for
from flask_login import LoginManager, UserMixin, current_user, login_required, login_user, logout_user
from flask_wtf.csrf import CSRFError, CSRFProtect
from werkzeug.security import check_password_hash, generate_password_hash

PROJECT_DIR = Path(__file__).resolve().parent.parent
if str(PROJECT_DIR) not in sys.path:
    sys.path.insert(0, str(PROJECT_DIR))

from authbind_utils import PRIVILEGED_PORT_CUTOFF, get_authbind_port_status
from device_defs import DeviceDefinition, find_device_by_signature, load_device_definitions
from protocols import discover_protocol_backends


BASE_DIR = Path(__file__).resolve().parent
EMULATOR_SCRIPT = PROJECT_DIR / "plc_emulator.py"
HMI_SCRIPT = PROJECT_DIR / "hmi_client.py"
LOG_DIR = BASE_DIR / "logs"
HMI_LOG_DIR = BASE_DIR / "hmi_logs"
HMI_STATUS_DIR = BASE_DIR / "hmi_status"
HMI_COMMAND_DIR = BASE_DIR / "hmi_commands"
FAULT_COMMAND_DIR = BASE_DIR / "fault_commands"
FAULT_STATUS_DIR = BASE_DIR / "fault_status"
REGISTRY_FILE = BASE_DIR / "instances.json"
HMI_REGISTRY_FILE = BASE_DIR / "hmi_instances.json"
DATABASE_FILE = BASE_DIR / "fleet_control.db"
SUPPORTED_HMI_PROTOCOLS = {"modbus", "s7comm"}
USERNAME_RE = re.compile(r"^[A-Za-z0-9_.-]{3,32}$")
PASSWORD_MIN_LENGTH = 8
FAILED_LOGIN_LIMIT = 5
FAILED_LOGIN_WINDOW_SECONDS = 300
FAILED_LOGIN_LOCKOUT_SECONDS = 60

for path in (LOG_DIR, HMI_LOG_DIR, HMI_STATUS_DIR, HMI_COMMAND_DIR, FAULT_COMMAND_DIR, FAULT_STATUS_DIR):
    path.mkdir(exist_ok=True)

app = Flask(__name__, static_folder=str(BASE_DIR / "static"), static_url_path="/static")
app.config.update(
    SECRET_KEY=os.environ.get("PLC_EM_SECRET_KEY", "dev-only-change-me"),
    WTF_CSRF_TIME_LIMIT=None,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("PLC_EM_SECURE_COOKIE", "").lower() in {"1", "true", "yes"},
)
csrf = CSRFProtect(app)
login_manager = LoginManager(app)
login_manager.login_view = "login"
login_manager.login_message = "Sign in to access the fleet."
login_manager.session_protection = "strong"

log = logging.getLogger("fleet_control")

instances: dict[str, dict] = {}
hmis: dict[str, dict] = {}
failed_login_attempts: dict[str, list[float]] = {}
login_lockouts: dict[str, float] = {}


class User(UserMixin):
    def __init__(self, user_id: int, username: str, created_at: str):
        self.id = str(user_id)
        self.username = username
        self.created_at = created_at


def get_db() -> sqlite3.Connection:
    if "db" not in g:
        conn = sqlite3.connect(DATABASE_FILE, timeout=30)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        g.db = conn
    return g.db


@app.teardown_appcontext
def close_db(_exc: BaseException | None) -> None:
    conn = g.pop("db", None)
    if conn is not None:
        conn.close()


def init_db() -> None:
    with sqlite3.connect(DATABASE_FILE, timeout=30) as conn:
        conn.execute("PRAGMA foreign_keys = ON")
        conn.execute("PRAGMA journal_mode = WAL")
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS saved_devices (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                name TEXT NOT NULL,
                device_type_id TEXT NOT NULL,
                config TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            )
            """
        )
        conn.commit()


def get_user_by_id(user_id: str | int) -> User | None:
    row = get_db().execute(
        "SELECT id, username, created_at FROM users WHERE id = ?",
        (int(user_id),),
    ).fetchone()
    if row is None:
        return None
    return User(int(row["id"]), str(row["username"]), str(row["created_at"]))


def get_user_auth_row(username: str) -> sqlite3.Row | None:
    return get_db().execute(
        "SELECT id, username, password_hash, created_at FROM users WHERE username = ?",
        (username,),
    ).fetchone()


def create_user(username: str, password: str) -> None:
    get_db().execute(
        "INSERT INTO users (username, password_hash) VALUES (?, ?)",
        (username, generate_password_hash(password)),
    )
    get_db().commit()


@login_manager.user_loader
def load_user(user_id: str) -> User | None:
    return get_user_by_id(user_id)


@login_manager.unauthorized_handler
def unauthorized() -> Any:
    if request.path.startswith("/api/"):
        return jsonify({"error": "authentication required"}), 401
    next_url = request.full_path if request.query_string else request.path
    return redirect(url_for("login", next=next_url))


@app.errorhandler(CSRFError)
def handle_csrf_error(exc: CSRFError):
    if request.path.startswith("/api/"):
        return jsonify({"error": exc.description}), 400
    flash("Security check failed. Reload the page and try again.", "error")
    return redirect(request.referrer or url_for("login"))


def bootstrap_state() -> None:
    init_db()
    load_registry()


def get_protocol_backends() -> dict[str, type]:
    return discover_protocol_backends()


def get_device_types() -> tuple[dict[str, DeviceDefinition], list[dict[str, str]]]:
    devices, errors = load_device_definitions()
    return devices, [error.to_dict() for error in errors]


def get_host_addresses() -> list[str]:
    addresses = {"0.0.0.0", "127.0.0.1"}
    hostname = socket.gethostname()
    try:
        for info in socket.getaddrinfo(hostname, None, socket.AF_INET):
            addresses.add(info[4][0])
    except socket.gaierror:
        pass

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        for _, ifname in socket.if_nameindex():
            try:
                packed_name = struct.pack("256s", ifname[:15].encode("utf-8"))
                result = fcntl.ioctl(sock.fileno(), 0x8915, packed_name)
                addresses.add(socket.inet_ntoa(result[20:24]))
            except OSError:
                continue
    finally:
        sock.close()

    def sort_key(value: str) -> tuple[int, str]:
        if value == "0.0.0.0":
            return (0, value)
        if value == "127.0.0.1":
            return (1, value)
        return (2, value)

    return sorted(addresses, key=sort_key)


def device_type_payload() -> dict[str, object]:
    devices, errors = get_device_types()
    available_backends = set(get_protocol_backends())
    payload: dict[str, dict[str, object]] = {}
    for key, device in devices.items():
        payload[key] = {
            **device.to_dict(),
            "implemented": device.protocol in available_backends,
            "hmi_supported": device.protocol in SUPPORTED_HMI_PROTOCOLS,
        }
    return {"devices": payload, "errors": errors}


def infer_device_type_id(cfg: dict) -> str | None:
    devices, _ = get_device_types()
    match = find_device_by_signature(
        devices,
        cfg.get("vendor"),
        cfg.get("model"),
        cfg.get("protocol"),
    )
    return match.id if match else None


def resolve_device_config(body: dict) -> tuple[dict, str | None]:
    devices, _ = get_device_types()
    device_type_id = body.get("device_type") or body.get("plc_type")
    if device_type_id and device_type_id not in devices:
        raise ValueError(f"unknown device_type '{device_type_id}'")
    preset = devices.get(device_type_id) if device_type_id else None

    protocol = (body.get("protocol") or (preset.protocol if preset else None) or "").strip()
    vendor = (body.get("vendor") or (preset.vendor if preset else "Generic Controls Inc.")).strip()
    model = (body.get("model") or (preset.model if preset else "GC-3000")).strip()
    product_code = (body.get("product_code") or (preset.product_code if preset else "GC3000")).strip()
    device_class = (body.get("device_class") or (preset.device_class if preset else "plc")).strip()

    resolved = {
        "device_type": device_type_id,
        "device_class": device_class,
        "vendor": vendor,
        "model": model,
        "protocol": protocol,
        "product_code": product_code,
    }
    return resolved, device_type_id


def normalize_instance_config(body: dict) -> dict[str, Any]:
    name = str(body.get("name") or "").strip()
    host = str(body.get("host") or "").strip()
    raw_port = body.get("port")
    raw_unit_id = body.get("unit_id", 1)
    verbose = bool(body.get("verbose", False))
    autostart = bool(body.get("autostart", True))
    override_identity = bool(body.get("override_identity", False))

    try:
        resolved, device_type_id = resolve_device_config(body)
    except ValueError as exc:
        raise ValueError(str(exc)) from exc

    if not name or not host or raw_port in (None, ""):
        raise ValueError("name, host, and port are required")
    try:
        port = int(raw_port)
        unit_id = int(raw_unit_id)
    except (TypeError, ValueError) as exc:
        raise ValueError("port and unit_id must be integers") from exc
    if not (1 <= port <= 65535):
        raise ValueError("port must be between 1 and 65535")
    if not (0 <= unit_id <= 247):
        raise ValueError("unit_id must be between 0 and 247")
    if not resolved["protocol"]:
        raise ValueError("protocol is required")

    return {
        "name": name,
        "host": host,
        "port": port,
        "unit_id": unit_id,
        "device_type": device_type_id,
        "device_class": resolved["device_class"],
        "vendor": resolved["vendor"],
        "model": resolved["model"],
        "protocol": resolved["protocol"],
        "product_code": resolved["product_code"],
        "verbose": verbose,
        "autostart": autostart,
        "override_identity": override_identity,
    }


def instance_conflicts(name: str, host: str, port: int) -> str | None:
    for cfg in instances.values():
        if cfg["host"] == host and cfg["port"] == port:
            return f"{host}:{port} is already used by '{cfg['name']}'"
        if cfg["name"] == name:
            return f"an instance named '{name}' already exists"
    return None


def create_instance_from_config(config: dict[str, Any]) -> tuple[dict, str | None]:
    conflict = instance_conflicts(config["name"], config["host"], int(config["port"]))
    if conflict:
        raise ValueError(conflict)

    iid = uuid.uuid4().hex[:8]
    instances[iid] = {
        "name": config["name"],
        "host": config["host"],
        "port": int(config["port"]),
        "unit_id": int(config["unit_id"]),
        "device_type": config.get("device_type"),
        "device_class": config["device_class"],
        "vendor": config["vendor"],
        "model": config["model"],
        "protocol": config["protocol"],
        "product_code": config["product_code"],
        "verbose": bool(config.get("verbose", False)),
        "override_identity": bool(config.get("override_identity", False)),
        "pid": None,
        "log_file": str(LOG_DIR / f"{iid}.log"),
        "fault_command_file": str(FAULT_COMMAND_DIR / f"{iid}.jsonl"),
        "fault_status_file": str(FAULT_STATUS_DIR / f"{iid}.json"),
        "created_at": time.time(),
    }
    save_registry()
    warning: str | None = None
    if config.get("autostart", True):
        ok, msg = start_instance(iid)
        if not ok:
            warning = f"created but failed to start: {msg}"
    return public_view(iid), warning


def _pid_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except (OSError, ProcessLookupError):
        return False
    return True


def _load_json_dict(path: Path) -> dict[str, dict]:
    if not path.exists():
        return {}
    try:
        raw = json.loads(path.read_text())
    except (json.JSONDecodeError, OSError):
        return {}
    return raw if isinstance(raw, dict) else {}


def _save_json_dict(path: Path, store: dict[str, dict]) -> None:
    path.write_text(json.dumps(store, indent=2))


def load_plc_registry() -> None:
    instances.clear()
    for iid, cfg in _load_json_dict(REGISTRY_FILE).items():
        cfg["pid"] = cfg.get("pid")
        cfg["device_type"] = cfg.get("device_type") or cfg.get("plc_type") or infer_device_type_id(cfg)
        cfg["device_class"] = cfg.get("device_class") or "plc"
        cfg["override_identity"] = bool(cfg.get("override_identity", False))
        cfg.setdefault("fault_command_file", str(FAULT_COMMAND_DIR / f"{iid}.jsonl"))
        cfg.setdefault("fault_status_file", str(FAULT_STATUS_DIR / f"{iid}.json"))
        if cfg.get("pid") and not _pid_alive(cfg["pid"]):
            cfg["pid"] = None
        instances[iid] = cfg


def load_hmi_registry() -> None:
    hmis.clear()
    for hid, cfg in _load_json_dict(HMI_REGISTRY_FILE).items():
        cfg["pid"] = cfg.get("pid")
        cfg.setdefault("status_file", str(HMI_STATUS_DIR / f"{hid}.json"))
        cfg.setdefault("command_file", str(HMI_COMMAND_DIR / f"{hid}.jsonl"))
        cfg.setdefault("poll_interval", 1.0)
        parent_cfg = instances.get(cfg.get("plc_id", ""))
        cfg["device_type"] = cfg.get("device_type") or cfg.get("plc_type") or (parent_cfg or {}).get("device_type")
        cfg["device_class"] = cfg.get("device_class") or (parent_cfg or {}).get("device_class") or "plc"
        if cfg.get("pid") and not _pid_alive(cfg["pid"]):
            cfg["pid"] = None
        hmis[hid] = cfg


def load_registry() -> None:
    load_plc_registry()
    load_hmi_registry()


def save_registry() -> None:
    _save_json_dict(REGISTRY_FILE, instances)
    _save_json_dict(HMI_REGISTRY_FILE, hmis)


def build_device_argv(_process_id: str, cfg: dict) -> list[str]:
    argv = [
        sys.executable,
        str(EMULATOR_SCRIPT),
        "--host",
        cfg["host"],
        "--port",
        str(cfg["port"]),
        "--protocol",
        cfg["protocol"],
        "--unit-id",
        str(cfg["unit_id"]),
        "--name",
        cfg["name"],
        "--vendor",
        cfg["vendor"],
        "--model",
        cfg["model"],
        "--product-code",
        cfg["product_code"],
    ]
    if cfg.get("fault_command_file"):
        argv.extend(["--fault-command-file", cfg["fault_command_file"]])
    if cfg.get("fault_status_file"):
        argv.extend(["--fault-status-file", cfg["fault_status_file"]])
    if cfg.get("device_type"):
        argv.extend(["--device-type", cfg["device_type"]])
    if cfg.get("verbose"):
        argv.append("-v")
    if cfg["port"] < PRIVILEGED_PORT_CUTOFF and shutil.which("authbind"):
        argv = ["authbind", "--deep"] + argv
    return argv


def build_hmi_argv(process_id: str, cfg: dict) -> list[str]:
    argv = [
        sys.executable,
        str(HMI_SCRIPT),
        "--hmi-id",
        process_id,
        "--device-id",
        cfg["plc_id"],
        "--name",
        cfg["name"],
        "--host",
        cfg["host"],
        "--port",
        str(cfg["port"]),
        "--protocol",
        cfg["protocol"],
        "--unit-id",
        str(cfg["unit_id"]),
        "--vendor",
        cfg["vendor"],
        "--model",
        cfg["model"],
        "--product-code",
        cfg["product_code"],
        "--poll-interval",
        str(cfg.get("poll_interval", 1.0)),
        "--status-file",
        cfg["status_file"],
        "--command-file",
        cfg["command_file"],
    ]
    if cfg.get("device_type"):
        argv.extend(["--device-type", cfg["device_type"]])
    if cfg.get("verbose"):
        argv.append("-v")
    return argv


def _start_managed_process(
    store: dict[str, dict],
    process_id: str,
    *,
    build_argv: Callable[[str, dict], list[str]],
    cwd: Path,
    log_dir: Path,
    preflight: Callable[[dict], tuple[bool, str]] | None = None,
) -> tuple[bool, str]:
    cfg = store[process_id]
    if cfg.get("pid") and _pid_alive(cfg["pid"]):
        return False, "already running"
    if preflight is not None:
        ok, message = preflight(cfg)
        if not ok:
            return False, message

    log_path = log_dir / f"{process_id}.log"
    cfg["log_file"] = str(log_path)
    argv = build_argv(process_id, cfg)
    log_fh = open(log_path, "a")
    log_fh.write(f"\n--- launching: {' '.join(argv)} ---\n")
    log_fh.flush()

    try:
        proc = subprocess.Popen(
            argv,
            stdout=log_fh,
            stderr=subprocess.STDOUT,
            cwd=str(cwd),
            start_new_session=True,
        )
    except OSError as exc:
        log_fh.write(f"--- failed to launch: {exc} ---\n")
        log_fh.close()
        return False, str(exc)

    cfg["pid"] = proc.pid
    save_registry()
    time.sleep(0.4)
    if not _pid_alive(proc.pid):
        cfg["pid"] = None
        save_registry()
        return False, "process exited immediately - check its log"
    return True, "started"


def _stop_managed_process(store: dict[str, dict], process_id: str) -> tuple[bool, str]:
    cfg = store[process_id]
    pid = cfg.get("pid")
    if not pid or not _pid_alive(pid):
        cfg["pid"] = None
        save_registry()
        return False, "not running"
    try:
        os.kill(pid, signal.SIGTERM)
    except OSError:
        pass
    for _ in range(20):
        if not _pid_alive(pid):
            break
        time.sleep(0.1)
    else:
        try:
            os.kill(pid, signal.SIGKILL)
        except OSError:
            pass
    cfg["pid"] = None
    save_registry()
    return True, "stopped"


def tail_log_from_cfg(cfg: dict, default_path: Path, lines: int = 200) -> str:
    log_path = Path(cfg.get("log_file", default_path))
    if not log_path.exists():
        return ""
    with log_path.open("r", errors="replace") as handle:
        all_lines = handle.readlines()
    return "".join(all_lines[-lines:])


def preflight_device(cfg: dict) -> tuple[bool, str]:
    if cfg["protocol"] not in get_protocol_backends():
        return False, f"protocol backend '{cfg['protocol']}' is not installed"
    return True, "ok"


def preflight_hmi(cfg: dict) -> tuple[bool, str]:
    if cfg["protocol"] not in SUPPORTED_HMI_PROTOCOLS:
        return False, f"HMI client support for protocol '{cfg['protocol']}' is not implemented"
    return True, "ok"


def start_instance(iid: str) -> tuple[bool, str]:
    return _start_managed_process(
        instances,
        iid,
        build_argv=build_device_argv,
        cwd=PROJECT_DIR,
        log_dir=LOG_DIR,
        preflight=preflight_device,
    )


def stop_instance(iid: str) -> tuple[bool, str]:
    return _stop_managed_process(instances, iid)


def get_hmi_ids_for_device(device_id: str) -> list[str]:
    ids = [hid for hid, cfg in hmis.items() if cfg.get("plc_id") == device_id]
    return sorted(ids, key=lambda hid: hmis[hid].get("created_at", 0))


def get_hmi_id_for_device(device_id: str) -> str | None:
    ids = get_hmi_ids_for_device(device_id)
    return ids[0] if ids else None


def sync_hmi_target_from_device(hmi_cfg: dict, device_cfg: dict) -> None:
    hmi_cfg["host"] = device_cfg["host"]
    hmi_cfg["port"] = device_cfg["port"]
    hmi_cfg["protocol"] = device_cfg["protocol"]
    hmi_cfg["unit_id"] = device_cfg["unit_id"]
    hmi_cfg["vendor"] = device_cfg["vendor"]
    hmi_cfg["model"] = device_cfg["model"]
    hmi_cfg["product_code"] = device_cfg["product_code"]
    hmi_cfg["device_type"] = device_cfg.get("device_type")
    hmi_cfg["device_class"] = device_cfg.get("device_class", "plc")


def start_hmi(hmi_id: str) -> tuple[bool, str]:
    hmi_cfg = hmis[hmi_id]
    device_cfg = instances.get(hmi_cfg["plc_id"])
    if device_cfg:
        sync_hmi_target_from_device(hmi_cfg, device_cfg)
    return _start_managed_process(
        hmis,
        hmi_id,
        build_argv=build_hmi_argv,
        cwd=PROJECT_DIR,
        log_dir=HMI_LOG_DIR,
        preflight=preflight_hmi,
    )


def stop_hmi(hmi_id: str) -> tuple[bool, str]:
    return _stop_managed_process(hmis, hmi_id)


def read_hmi_status(hmi_id: str) -> dict:
    cfg = hmis[hmi_id]
    status = {
        "hmi_id": hmi_id,
        "device_id": cfg["plc_id"],
        "device_type": cfg.get("device_type"),
        "protocol": cfg["protocol"],
        "state": "starting" if cfg.get("pid") else "stopped",
        "connected": False,
        "unsupported": cfg["protocol"] not in SUPPORTED_HMI_PROTOCOLS,
        "error": None,
        "snapshot": None,
        "recent_events": [],
        "last_poll_ts": None,
        "last_command_id": None,
        "updated_at": None,
    }
    status_path = Path(cfg["status_file"])
    if status_path.exists():
        try:
            parsed = json.loads(status_path.read_text())
            if isinstance(parsed, dict):
                status.update(parsed)
        except (OSError, json.JSONDecodeError):
            status["error"] = "failed to parse HMI status file"
    running = bool(cfg.get("pid")) and _pid_alive(cfg["pid"])
    status["running"] = running
    if cfg["protocol"] not in SUPPORTED_HMI_PROTOCOLS:
        status["state"] = "unsupported"
        status["error"] = status["error"] or f"HMI client support for protocol '{cfg['protocol']}' is not implemented"
    elif not running:
        status["state"] = "stopped"
        status["connected"] = False
    return status


def append_hmi_command(hmi_id: str, point_id: str, value: Any) -> str:
    cfg = hmis[hmi_id]
    command_id = uuid.uuid4().hex[:8]
    command = {
        "id": command_id,
        "point_id": point_id,
        "value": value,
        "ts": time.time(),
    }
    command_file = Path(cfg["command_file"])
    command_file.parent.mkdir(exist_ok=True)
    with command_file.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(command) + "\n")
    return command_id


def public_hmi_view(hmi_id: str) -> dict:
    cfg = hmis[hmi_id]
    running = bool(cfg.get("pid")) and _pid_alive(cfg["pid"])
    return {
        "id": hmi_id,
        "device_id": cfg["plc_id"],
        "device_type": cfg.get("device_type"),
        "device_class": cfg.get("device_class", "plc"),
        "name": cfg["name"],
        "host": cfg["host"],
        "port": cfg["port"],
        "protocol": cfg["protocol"],
        "unit_id": cfg["unit_id"],
        "poll_interval": cfg.get("poll_interval", 1.0),
        "running": running,
        "pid": cfg.get("pid") if running else None,
        "supported": cfg["protocol"] in SUPPORTED_HMI_PROTOCOLS,
    }


def public_view(iid: str) -> dict:
    cfg = instances[iid]
    running = bool(cfg.get("pid")) and _pid_alive(cfg["pid"])
    hmi_id = get_hmi_id_for_device(iid)
    return {
        "id": iid,
        "name": cfg["name"],
        "host": cfg["host"],
        "port": cfg["port"],
        "unit_id": cfg["unit_id"],
        "device_type": cfg.get("device_type"),
        "device_class": cfg.get("device_class", "plc"),
        "vendor": cfg["vendor"],
        "model": cfg["model"],
        "protocol": cfg["protocol"],
        "product_code": cfg["product_code"],
        "verbose": cfg.get("verbose", False),
        "override_identity": cfg.get("override_identity", False),
        "running": running,
        "pid": cfg.get("pid") if running else None,
        "privileged_port": cfg["port"] < PRIVILEGED_PORT_CUTOFF,
        "hmi_supported": cfg["protocol"] in SUPPORTED_HMI_PROTOCOLS,
        "hmi": public_hmi_view(hmi_id) if hmi_id else None,
    }


def delete_hmi(hmi_id: str) -> None:
    if hmi_id not in hmis:
        return
    stop_hmi(hmi_id)
    cfg = hmis[hmi_id]
    for key, default_dir, suffix in (
        ("log_file", HMI_LOG_DIR, ".log"),
        ("status_file", HMI_STATUS_DIR, ".json"),
        ("command_file", HMI_COMMAND_DIR, ".jsonl"),
    ):
        path = Path(cfg.get(key, default_dir / f"{hmi_id}{suffix}"))
        if path.exists():
            path.unlink()
    del hmis[hmi_id]
    save_registry()


def tail_log(iid: str, lines: int = 200) -> str:
    cfg = instances.get(iid)
    if not cfg:
        return ""
    return tail_log_from_cfg(cfg, LOG_DIR / f"{iid}.log", lines)


def read_fault_status_from_cfg(cfg: dict) -> dict[str, Any]:
    status_path = Path(cfg.get("fault_status_file", ""))
    payload: dict[str, Any] = {"updated_at": None, "faults": []}
    if not status_path.exists():
        return payload
    try:
        raw = json.loads(status_path.read_text())
    except (OSError, json.JSONDecodeError):
        return payload
    if isinstance(raw, dict):
        payload["updated_at"] = raw.get("updated_at")
        faults = raw.get("faults", [])
        if isinstance(faults, list):
            payload["faults"] = faults
    return payload


def faultable_points_for_instance(cfg: dict) -> list[dict[str, Any]]:
    devices, _ = get_device_types()
    device = devices.get(cfg.get("device_type") or "")
    if device is None:
        return []
    points: list[dict[str, Any]] = []
    for point in device.points:
        if point.fault is None:
            continue
        points.append(
            {
                "id": point.id,
                "label": point.label,
                "kind": point.kind,
                "access": point.access,
                "modes": list(point.fault.modes),
                "defaults": dict(point.fault.defaults),
            }
        )
    return points


def append_fault_command(iid: str, payload: dict[str, Any]) -> None:
    cfg = instances[iid]
    command_file = Path(cfg["fault_command_file"])
    command_file.parent.mkdir(exist_ok=True)
    with command_file.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(payload) + "\n")


def _login_attempt_key(username: str, remote_addr: str | None) -> str:
    return f"{username.strip().lower()}|{remote_addr or '-'}"


def _prune_failed_attempts(key: str, now: float) -> None:
    attempts = [ts for ts in failed_login_attempts.get(key, []) if now - ts <= FAILED_LOGIN_WINDOW_SECONDS]
    if attempts:
        failed_login_attempts[key] = attempts
    else:
        failed_login_attempts.pop(key, None)
    expires = login_lockouts.get(key)
    if expires is not None and expires <= now:
        login_lockouts.pop(key, None)


def login_lockout_remaining(username: str, remote_addr: str | None) -> int:
    key = _login_attempt_key(username, remote_addr)
    now = time.time()
    _prune_failed_attempts(key, now)
    expires = login_lockouts.get(key)
    if expires is None:
        return 0
    return max(0, int(expires - now))


def record_failed_login(username: str, remote_addr: str | None) -> int:
    key = _login_attempt_key(username, remote_addr)
    now = time.time()
    _prune_failed_attempts(key, now)
    attempts = failed_login_attempts.setdefault(key, [])
    attempts.append(now)
    if len(attempts) >= FAILED_LOGIN_LIMIT:
        login_lockouts[key] = now + FAILED_LOGIN_LOCKOUT_SECONDS
        return FAILED_LOGIN_LOCKOUT_SECONDS
    return 0


def clear_failed_logins(username: str, remote_addr: str | None) -> None:
    key = _login_attempt_key(username, remote_addr)
    failed_login_attempts.pop(key, None)
    login_lockouts.pop(key, None)


def is_safe_next_url(target: str | None) -> bool:
    if not target:
        return False
    host_url = request.host_url
    ref_url = urlparse(host_url)
    test_url = urlparse(urljoin(host_url, target))
    return test_url.scheme in {"http", "https"} and ref_url.netloc == test_url.netloc


def validate_registration_form(username: str, password: str, confirm_password: str) -> str | None:
    if not USERNAME_RE.fullmatch(username):
        return "Username must be 3-32 characters using letters, numbers, dot, dash, or underscore."
    if len(password) < PASSWORD_MIN_LENGTH:
        return f"Password must be at least {PASSWORD_MIN_LENGTH} characters."
    if password != confirm_password:
        return "Passwords do not match."
    if get_user_auth_row(username) is not None:
        return "That username is already registered."
    return None


def current_user_id() -> int:
    return int(str(current_user.get_id()))


def saved_device_row_to_payload(row: sqlite3.Row, device_types: dict[str, DeviceDefinition]) -> dict[str, Any]:
    try:
        config = json.loads(str(row["config"]))
    except json.JSONDecodeError:
        config = {}
    device_type_id = str(row["device_type_id"])
    device = device_types.get(device_type_id)
    protocol = config.get("protocol") or (device.protocol if device else None)
    return {
        "id": int(row["id"]),
        "name": str(row["name"]),
        "device_type_id": device_type_id,
        "created_at": str(row["created_at"]),
        "updated_at": str(row["updated_at"]),
        "config": config,
        "device": {
            "display_name": device.display_name,
            "device_class": device.device_class,
            "protocol": device.protocol,
            "default_port": device.default_port,
            "implemented": device.protocol in get_protocol_backends(),
            "hmi_supported": device.protocol in SUPPORTED_HMI_PROTOCOLS,
        }
        if device
        else None,
        "available": device is not None,
        "protocol": protocol,
    }


def fetch_saved_devices_for_user(user_id: int) -> list[dict[str, Any]]:
    rows = get_db().execute(
        """
        SELECT id, name, device_type_id, config, created_at, updated_at
        FROM saved_devices
        WHERE user_id = ?
        ORDER BY updated_at DESC, id DESC
        """,
        (user_id,),
    ).fetchall()
    device_types, _ = get_device_types()
    return [saved_device_row_to_payload(row, device_types) for row in rows]


def fetch_saved_device_row_for_user(user_id: int, saved_device_id: int) -> sqlite3.Row | None:
    return get_db().execute(
        """
        SELECT id, user_id, name, device_type_id, config, created_at, updated_at
        FROM saved_devices
        WHERE id = ? AND user_id = ?
        """,
        (saved_device_id, user_id),
    ).fetchone()


def persist_saved_device(user_id: int, payload: dict[str, Any], saved_device_id: int | None = None) -> tuple[dict[str, Any], bool]:
    save_name = str(payload.get("save_name") or "").strip()
    if not save_name:
        raise ValueError("save_name is required")
    if len(save_name) > 80:
        raise ValueError("save_name must be 80 characters or fewer")

    config = normalize_instance_config(payload)
    config_blob = json.dumps(config)
    db = get_db()

    if saved_device_id is not None:
        existing = fetch_saved_device_row_for_user(user_id, saved_device_id)
        if existing is None:
            raise LookupError("no such saved device")
        if save_name == str(existing["name"]):
            db.execute(
                """
                UPDATE saved_devices
                SET device_type_id = ?, config = ?, updated_at = CURRENT_TIMESTAMP
                WHERE id = ? AND user_id = ?
                """,
                (config["device_type"], config_blob, saved_device_id, user_id),
            )
            db.commit()
            row = fetch_saved_device_row_for_user(user_id, saved_device_id)
            if row is None:
                raise LookupError("no such saved device")
            device_types, _ = get_device_types()
            return saved_device_row_to_payload(row, device_types), False

    cursor = db.execute(
        """
        INSERT INTO saved_devices (user_id, name, device_type_id, config)
        VALUES (?, ?, ?, ?)
        """,
        (user_id, save_name, config["device_type"], config_blob),
    )
    db.commit()
    row = fetch_saved_device_row_for_user(user_id, int(cursor.lastrowid))
    if row is None:
        raise LookupError("failed to reload saved device")
    device_types, _ = get_device_types()
    return saved_device_row_to_payload(row, device_types), True


@app.get("/register")
def register():
    if current_user.is_authenticated:
        return redirect(url_for("index"))
    return render_template("auth.html", mode="register", title="Register")


@app.post("/register")
def register_submit():
    if current_user.is_authenticated:
        return redirect(url_for("index"))
    username = str(request.form.get("username") or "").strip()
    password = str(request.form.get("password") or "")
    confirm_password = str(request.form.get("confirm_password") or "")
    error = validate_registration_form(username, password, confirm_password)
    if error:
        flash(error, "error")
        return render_template("auth.html", mode="register", title="Register", form_data={"username": username}), 400
    create_user(username, password)
    flash("Account created. Sign in to continue.", "success")
    return redirect(url_for("login"))


@app.get("/login")
def login():
    if current_user.is_authenticated:
        return redirect(url_for("index"))
    return render_template("auth.html", mode="login", title="Login")


@app.post("/login")
def login_submit():
    if current_user.is_authenticated:
        return redirect(url_for("index"))
    username = str(request.form.get("username") or "").strip()
    password = str(request.form.get("password") or "")
    remaining = login_lockout_remaining(username, request.remote_addr)
    if remaining > 0:
        flash(f"Too many failed attempts. Try again in {remaining}s.", "error")
        return render_template("auth.html", mode="login", title="Login", form_data={"username": username}), 429

    row = get_user_auth_row(username)
    if row is None or not check_password_hash(str(row["password_hash"]), password):
        lockout = record_failed_login(username, request.remote_addr)
        log.warning("Failed login for username=%r from ip=%s", username, request.remote_addr)
        message = "Invalid username or password."
        if lockout > 0:
            message = f"Too many failed attempts. Try again in {lockout}s."
        flash(message, "error")
        return render_template("auth.html", mode="login", title="Login", form_data={"username": username}), (429 if lockout > 0 else 401)

    clear_failed_logins(username, request.remote_addr)
    user = User(int(row["id"]), str(row["username"]), str(row["created_at"]))
    login_user(user)
    next_url = str(request.args.get("next") or request.form.get("next") or "")
    if is_safe_next_url(next_url):
        return redirect(next_url)
    return redirect(url_for("index"))


@app.post("/logout")
@login_required
def logout():
    logout_user()
    flash("Signed out.", "success")
    return redirect(url_for("login"))


@app.get("/api/device-types")
@login_required
def api_device_types():
    return jsonify(device_type_payload())


@app.get("/api/plc-types")
@login_required
def api_plc_types_alias():
    return jsonify(device_type_payload())


@app.get("/api/instances")
@login_required
def api_list():
    return jsonify([public_view(iid) for iid in instances])


@app.post("/api/instances")
@login_required
def api_create():
    body = request.get_json(force=True, silent=True) or {}
    try:
        config = normalize_instance_config(body)
        instance, warning = create_instance_from_config(config)
    except ValueError as exc:
        message = str(exc)
        status = 409 if "already exists" in message or "already used" in message else 400
        return jsonify({"error": message}), status
    response_body: dict[str, Any] = {"instance": instance}
    if warning:
        response_body["warning"] = warning
    return jsonify(response_body), 201


@app.post("/api/instances/<iid>/start")
@login_required
def api_start(iid: str):
    if iid not in instances:
        return jsonify({"error": "no such instance"}), 404
    ok, msg = start_instance(iid)
    return jsonify({"ok": ok, "message": msg, "instance": public_view(iid)}), (200 if ok else 409)


@app.post("/api/instances/<iid>/stop")
@login_required
def api_stop(iid: str):
    if iid not in instances:
        return jsonify({"error": "no such instance"}), 404
    ok, msg = stop_instance(iid)
    return jsonify({"ok": ok, "message": msg, "instance": public_view(iid)}), 200


@app.delete("/api/instances/<iid>")
@login_required
def api_delete(iid: str):
    if iid not in instances:
        return jsonify({"error": "no such instance"}), 404
    for hmi_id in list(get_hmi_ids_for_device(iid)):
        delete_hmi(hmi_id)
    stop_instance(iid)
    log_path = LOG_DIR / f"{iid}.log"
    if log_path.exists():
        log_path.unlink()
    for key in ("fault_command_file", "fault_status_file"):
        path = Path(instances[iid].get(key, ""))
        if path.exists():
            path.unlink()
    del instances[iid]
    save_registry()
    return jsonify({"ok": True, "cascade": "attached HMI stopped and removed"}), 200


@app.get("/api/instances/<iid>/logs")
@login_required
def api_logs(iid: str):
    if iid not in instances:
        return jsonify({"error": "no such instance"}), 404
    lines = request.args.get("lines", default=200, type=int)
    return jsonify({"log": tail_log(iid, lines)})


@app.get("/api/instances/<iid>/faults")
@login_required
def api_instance_faults(iid: str):
    if iid not in instances:
        return jsonify({"error": "no such instance"}), 404
    cfg = instances[iid]
    return jsonify(
        {
            "instance_id": iid,
            "running": bool(cfg.get("pid")) and _pid_alive(cfg["pid"]),
            "supported_points": faultable_points_for_instance(cfg),
            "active_faults": read_fault_status_from_cfg(cfg).get("faults", []),
            "updated_at": read_fault_status_from_cfg(cfg).get("updated_at"),
        }
    )


@app.post("/api/instances/<iid>/fault")
@login_required
def api_instance_fault(iid: str):
    if iid not in instances:
        return jsonify({"error": "no such instance"}), 404
    cfg = instances[iid]
    if not (cfg.get("pid") and _pid_alive(cfg["pid"])):
        return jsonify({"error": "instance must be running to inject a fault"}), 409

    body = request.get_json(force=True, silent=True) or {}
    point_id = str(body.get("point") or "").strip()
    mode = str(body.get("mode") or "").strip()
    params = body.get("params", {})
    if not point_id or not mode:
        return jsonify({"error": "point and mode are required"}), 400
    if not isinstance(params, dict):
        return jsonify({"error": "params must be an object when present"}), 400

    supported = {point["id"]: point for point in faultable_points_for_instance(cfg)}
    point = supported.get(point_id)
    if point is None:
        return jsonify({"error": f"point '{point_id}' is not fault-injectable for this device"}), 400
    if mode not in point["modes"]:
        return jsonify({"error": f"fault mode '{mode}' is not supported for point '{point_id}'"}), 400

    append_fault_command(
        iid,
        {
            "action": "set",
            "point": point_id,
            "mode": mode,
            "params": params,
            "ts": time.time(),
        },
    )
    return jsonify({"ok": True}), 202


@app.post("/api/instances/<iid>/fault/clear")
@login_required
def api_instance_fault_clear(iid: str):
    if iid not in instances:
        return jsonify({"error": "no such instance"}), 404
    cfg = instances[iid]
    if not (cfg.get("pid") and _pid_alive(cfg["pid"])):
        return jsonify({"error": "instance must be running to clear a fault"}), 409

    body = request.get_json(force=True, silent=True) or {}
    point_id = str(body.get("point") or "").strip()
    if not point_id:
        return jsonify({"error": "point is required"}), 400
    supported = {point["id"]: point for point in faultable_points_for_instance(cfg)}
    if point_id not in supported:
        return jsonify({"error": f"point '{point_id}' is not fault-injectable for this device"}), 400

    append_fault_command(
        iid,
        {
            "action": "clear",
            "point": point_id,
            "ts": time.time(),
        },
    )
    return jsonify({"ok": True}), 202


@app.post("/api/instances/<iid>/hmi")
@login_required
def api_open_hmi(iid: str):
    if iid not in instances:
        return jsonify({"error": "no such instance"}), 404
    device_cfg = instances[iid]
    if device_cfg["protocol"] not in SUPPORTED_HMI_PROTOCOLS:
        return jsonify({"error": f"HMI client support for protocol '{device_cfg['protocol']}' is not implemented"}), 501
    body = request.get_json(force=True, silent=True) or {}
    try:
        poll_interval = max(0.2, float(body.get("poll_interval", 1.0)))
    except (TypeError, ValueError):
        return jsonify({"error": "poll_interval must be numeric"}), 400

    hmi_id = get_hmi_id_for_device(iid)
    created = False
    if hmi_id is None:
        hmi_id = uuid.uuid4().hex[:8]
        hmis[hmi_id] = {
            "plc_id": iid,
            "name": f"{device_cfg['name']} HMI",
            "host": device_cfg["host"],
            "port": device_cfg["port"],
            "protocol": device_cfg["protocol"],
            "unit_id": device_cfg["unit_id"],
            "vendor": device_cfg["vendor"],
            "model": device_cfg["model"],
            "product_code": device_cfg["product_code"],
            "device_type": device_cfg.get("device_type"),
            "device_class": device_cfg.get("device_class", "plc"),
            "poll_interval": poll_interval,
            "pid": None,
            "log_file": str(HMI_LOG_DIR / f"{hmi_id}.log"),
            "status_file": str(HMI_STATUS_DIR / f"{hmi_id}.json"),
            "command_file": str(HMI_COMMAND_DIR / f"{hmi_id}.jsonl"),
            "created_at": time.time(),
        }
        created = True
    else:
        hmis[hmi_id]["poll_interval"] = poll_interval
        sync_hmi_target_from_device(hmis[hmi_id], device_cfg)

    save_registry()
    ok, msg = start_hmi(hmi_id)
    if not ok and msg != "already running":
        return jsonify({"error": msg}), 409
    return jsonify(
        {
            "ok": True,
            "message": "created" if created else msg,
            "hmi": public_hmi_view(hmi_id),
            "status": read_hmi_status(hmi_id),
        }
    ), (201 if created else 200)


@app.post("/api/hmi/<hmi_id>/stop")
@login_required
def api_hmi_stop(hmi_id: str):
    if hmi_id not in hmis:
        return jsonify({"error": "no such hmi"}), 404
    ok, msg = stop_hmi(hmi_id)
    return jsonify({"ok": ok, "message": msg, "hmi": public_hmi_view(hmi_id)}), 200


@app.delete("/api/hmi/<hmi_id>")
@login_required
def api_hmi_delete(hmi_id: str):
    if hmi_id not in hmis:
        return jsonify({"error": "no such hmi"}), 404
    delete_hmi(hmi_id)
    return jsonify({"ok": True}), 200


@app.get("/api/hmi/<hmi_id>/status")
@login_required
def api_hmi_status(hmi_id: str):
    if hmi_id not in hmis:
        return jsonify({"error": "no such hmi"}), 404
    return jsonify({"hmi": public_hmi_view(hmi_id), "status": read_hmi_status(hmi_id)})


@app.post("/api/hmi/<hmi_id>/command")
@login_required
def api_hmi_command(hmi_id: str):
    if hmi_id not in hmis:
        return jsonify({"error": "no such hmi"}), 404
    if not public_hmi_view(hmi_id)["running"]:
        return jsonify({"error": "hmi is not running"}), 409
    body = request.get_json(force=True, silent=True) or {}
    point_id = str(body.get("point_id") or "").strip()
    if not point_id:
        return jsonify({"error": "point_id is required"}), 400
    value = body.get("value")
    command_id = append_hmi_command(hmi_id, point_id, value)
    return jsonify({"ok": True, "command_id": command_id, "hmi": public_hmi_view(hmi_id)}), 202


@app.get("/api/authbind-status")
@login_required
def api_authbind_status():
    raw_port = request.args.get("port")
    if raw_port is None:
        return jsonify({"available": shutil.which("authbind") is not None})
    try:
        port = int(raw_port)
    except (TypeError, ValueError):
        return jsonify({"error": "port must be an integer"}), 400
    return jsonify(get_authbind_port_status(port).to_dict())


@app.get("/api/host-addresses")
@login_required
def api_host_addresses():
    return jsonify({"addresses": get_host_addresses()})


@app.get("/api/saved-devices")
@login_required
def api_saved_devices():
    return jsonify({"saved_devices": fetch_saved_devices_for_user(current_user_id())})


@app.post("/api/saved-devices")
@login_required
def api_saved_devices_create():
    body = request.get_json(force=True, silent=True) or {}
    try:
        saved_device, created = persist_saved_device(current_user_id(), body)
    except LookupError:
        return jsonify({"error": "no such saved device"}), 404
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400
    return jsonify({"saved_device": saved_device, "created": created}), 201


@app.put("/api/saved-devices/<int:saved_device_id>")
@login_required
def api_saved_devices_update(saved_device_id: int):
    body = request.get_json(force=True, silent=True) or {}
    try:
        saved_device, created = persist_saved_device(current_user_id(), body, saved_device_id=saved_device_id)
    except LookupError:
        return jsonify({"error": "no such saved device"}), 404
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400
    return jsonify({"saved_device": saved_device, "created": created}), 200


@app.delete("/api/saved-devices/<int:saved_device_id>")
@login_required
def api_saved_devices_delete(saved_device_id: int):
    row = fetch_saved_device_row_for_user(current_user_id(), saved_device_id)
    if row is None:
        return jsonify({"error": "no such saved device"}), 404
    get_db().execute(
        "DELETE FROM saved_devices WHERE id = ? AND user_id = ?",
        (saved_device_id, current_user_id()),
    )
    get_db().commit()
    return jsonify({"ok": True}), 200


@app.post("/api/saved-devices/<int:saved_device_id>/launch")
@login_required
def api_saved_devices_launch(saved_device_id: int):
    row = fetch_saved_device_row_for_user(current_user_id(), saved_device_id)
    if row is None:
        return jsonify({"error": "no such saved device"}), 404
    try:
        body = json.loads(str(row["config"]))
        config = normalize_instance_config(body)
        instance, warning = create_instance_from_config(config)
    except json.JSONDecodeError:
        return jsonify({"error": "saved device config is not valid JSON"}), 400
    except ValueError as exc:
        message = str(exc)
        status = 409 if "already exists" in message or "already used" in message else 400
        return jsonify({"error": message}), status
    response_body: dict[str, Any] = {"instance": instance}
    if warning:
        response_body["warning"] = warning
    return jsonify(response_body), 201


@app.get("/")
@login_required
def index():
    return render_template("index.html")


def parse_args():
    parser = argparse.ArgumentParser(description="Web control panel for simulated device fleet")
    parser.add_argument("--host", default="127.0.0.1", help="Address the web UI binds to")
    parser.add_argument("--port", type=int, default=8080, help="Port the web UI binds to")
    parser.add_argument("--debug", action="store_true", help="Run Flask in debug/reload mode")
    return parser.parse_args()


bootstrap_state()


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)-7s %(message)s")
    args = parse_args()
    app.run(host=args.host, port=args.port, debug=args.debug)

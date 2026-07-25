#!/usr/bin/env python3
"""Fleet control panel for PLC emulator and HMI client subprocesses."""

from __future__ import annotations

import argparse
import json
import os
import shutil
import signal
import subprocess
import sys
import time
import uuid
from pathlib import Path
from typing import Callable

from flask import Flask, jsonify, request, send_from_directory

PROJECT_DIR = Path(__file__).resolve().parent.parent
if str(PROJECT_DIR) not in sys.path:
    sys.path.insert(0, str(PROJECT_DIR))

from plc_types import PlcType, find_plc_type_by_signature, load_plc_types
from protocols import discover_protocol_backends


BASE_DIR = Path(__file__).resolve().parent
EMULATOR_SCRIPT = PROJECT_DIR / "plc_emulator.py"
HMI_SCRIPT = PROJECT_DIR / "hmi_client.py"
LOG_DIR = BASE_DIR / "logs"
HMI_LOG_DIR = BASE_DIR / "hmi_logs"
HMI_STATUS_DIR = BASE_DIR / "hmi_status"
HMI_COMMAND_DIR = BASE_DIR / "hmi_commands"
REGISTRY_FILE = BASE_DIR / "instances.json"
HMI_REGISTRY_FILE = BASE_DIR / "hmi_instances.json"
PRIVILEGED_PORT_CUTOFF = 1024
SUPPORTED_HMI_PROTOCOLS = {"modbus", "s7comm"}

for path in (LOG_DIR, HMI_LOG_DIR, HMI_STATUS_DIR, HMI_COMMAND_DIR):
    path.mkdir(exist_ok=True)

app = Flask(__name__, static_folder=str(BASE_DIR / "static"), static_url_path="/static")
instances: dict[str, dict] = {}
hmis: dict[str, dict] = {}


def get_protocol_backends() -> dict[str, type]:
    return discover_protocol_backends()


def get_plc_types() -> dict[str, PlcType]:
    return load_plc_types()


def plc_type_payload() -> dict[str, dict[str, object]]:
    available_backends = set(get_protocol_backends())
    payload: dict[str, dict[str, object]] = {}
    for key, plc_type in get_plc_types().items():
        payload[key] = {
            "vendor": plc_type.vendor,
            "model": plc_type.model,
            "protocol": plc_type.protocol,
            "default_port": plc_type.default_port,
            "product_code": plc_type.product_code,
            "implemented": plc_type.protocol in available_backends,
        }
    return payload


def infer_plc_type_id(cfg: dict) -> str | None:
    plc_types = get_plc_types()
    match = find_plc_type_by_signature(
        plc_types,
        cfg.get("vendor"),
        cfg.get("model"),
        cfg.get("protocol"),
    )
    return match.key if match else None


def resolve_plc_config(body: dict) -> tuple[dict, str | None]:
    plc_types = get_plc_types()
    plc_type_id = body.get("plc_type")
    if plc_type_id and plc_type_id not in plc_types:
        raise ValueError(f"unknown plc_type '{plc_type_id}'")
    preset = plc_types.get(plc_type_id) if plc_type_id else None

    protocol = (body.get("protocol") or (preset.protocol if preset else None) or "").strip()
    vendor = (body.get("vendor") or (preset.vendor if preset else "Generic Controls Inc.")).strip()
    model = (body.get("model") or (preset.model if preset else "GC-3000")).strip()
    product_code = (body.get("product_code") or (preset.product_code if preset else "GC3000")).strip()

    resolved = {
        "plc_type": plc_type_id,
        "vendor": vendor,
        "model": model,
        "protocol": protocol,
        "product_code": product_code,
    }
    return resolved, plc_type_id


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
        cfg["plc_type"] = cfg.get("plc_type") or infer_plc_type_id(cfg)
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
        if cfg.get("pid") and not _pid_alive(cfg["pid"]):
            cfg["pid"] = None
        hmis[hid] = cfg


def load_registry() -> None:
    load_plc_registry()
    load_hmi_registry()


def save_registry() -> None:
    _save_json_dict(REGISTRY_FILE, instances)
    _save_json_dict(HMI_REGISTRY_FILE, hmis)


def build_plc_argv(process_id: str, cfg: dict) -> list[str]:
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
    if cfg.get("plc_type"):
        argv.extend(["--plc-type", cfg["plc_type"]])
    if cfg.get("verbose"):
        argv.append("-v")

    if cfg["port"] < PRIVILEGED_PORT_CUTOFF and shutil.which("authbind"):
        argv = ["authbind", "--deep"] + argv
    return argv


def build_hmi_argv(process_id: str, cfg: dict) -> list[str]:
    return [
        sys.executable,
        str(HMI_SCRIPT),
        "--hmi-id",
        process_id,
        "--plc-id",
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


def preflight_plc(cfg: dict) -> tuple[bool, str]:
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
        build_argv=build_plc_argv,
        cwd=PROJECT_DIR,
        log_dir=LOG_DIR,
        preflight=preflight_plc,
    )


def stop_instance(iid: str) -> tuple[bool, str]:
    return _stop_managed_process(instances, iid)


def get_hmi_ids_for_plc(plc_id: str) -> list[str]:
    ids = [hid for hid, cfg in hmis.items() if cfg.get("plc_id") == plc_id]
    return sorted(ids, key=lambda hid: hmis[hid].get("created_at", 0))


def get_hmi_id_for_plc(plc_id: str) -> str | None:
    ids = get_hmi_ids_for_plc(plc_id)
    return ids[0] if ids else None


def sync_hmi_target_from_plc(hmi_cfg: dict, plc_cfg: dict) -> None:
    hmi_cfg["host"] = plc_cfg["host"]
    hmi_cfg["port"] = plc_cfg["port"]
    hmi_cfg["protocol"] = plc_cfg["protocol"]
    hmi_cfg["unit_id"] = plc_cfg["unit_id"]
    hmi_cfg["vendor"] = plc_cfg["vendor"]
    hmi_cfg["model"] = plc_cfg["model"]
    hmi_cfg["product_code"] = plc_cfg["product_code"]


def start_hmi(hmi_id: str) -> tuple[bool, str]:
    hmi_cfg = hmis[hmi_id]
    plc_cfg = instances.get(hmi_cfg["plc_id"])
    if plc_cfg:
        sync_hmi_target_from_plc(hmi_cfg, plc_cfg)
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
        "plc_id": cfg["plc_id"],
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


def append_hmi_command(hmi_id: str, action: str, value) -> str:
    cfg = hmis[hmi_id]
    command_id = uuid.uuid4().hex[:8]
    command = {
        "id": command_id,
        "action": action,
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
        "plc_id": cfg["plc_id"],
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
    hmi_id = get_hmi_id_for_plc(iid)
    return {
        "id": iid,
        "name": cfg["name"],
        "host": cfg["host"],
        "port": cfg["port"],
        "unit_id": cfg["unit_id"],
        "plc_type": cfg.get("plc_type"),
        "vendor": cfg["vendor"],
        "model": cfg["model"],
        "protocol": cfg["protocol"],
        "product_code": cfg["product_code"],
        "verbose": cfg.get("verbose", False),
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


@app.get("/api/plc-types")
def api_plc_types():
    return jsonify(plc_type_payload())


@app.get("/api/instances")
def api_list():
    return jsonify([public_view(iid) for iid in instances])


@app.post("/api/instances")
def api_create():
    body = request.get_json(force=True, silent=True) or {}
    name = (body.get("name") or "").strip()
    host = (body.get("host") or "").strip()
    port = body.get("port")
    unit_id = body.get("unit_id", 1)
    verbose = bool(body.get("verbose", False))
    autostart = bool(body.get("autostart", True))

    try:
        resolved, plc_type_id = resolve_plc_config(body)
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400

    if not name or not host or not port:
        return jsonify({"error": "name, host, and port are required"}), 400
    try:
        port = int(port)
        unit_id = int(unit_id)
    except (TypeError, ValueError):
        return jsonify({"error": "port and unit_id must be integers"}), 400

    if not (1 <= port <= 65535):
        return jsonify({"error": "port must be between 1 and 65535"}), 400
    if not (0 <= unit_id <= 247):
        return jsonify({"error": "unit_id must be between 0 and 247 (Modbus range)"}), 400
    if not resolved["protocol"]:
        return jsonify({"error": "protocol is required"}), 400

    for cfg in instances.values():
        if cfg["host"] == host and cfg["port"] == port:
            return jsonify({"error": f"{host}:{port} is already used by '{cfg['name']}'"}), 409
        if cfg["name"] == name:
            return jsonify({"error": f"an instance named '{name}' already exists"}), 409

    iid = uuid.uuid4().hex[:8]
    instances[iid] = {
        "name": name,
        "host": host,
        "port": port,
        "unit_id": unit_id,
        "plc_type": plc_type_id,
        "vendor": resolved["vendor"],
        "model": resolved["model"],
        "protocol": resolved["protocol"],
        "product_code": resolved["product_code"],
        "verbose": verbose,
        "pid": None,
        "log_file": str(LOG_DIR / f"{iid}.log"),
        "created_at": time.time(),
    }
    save_registry()

    if autostart:
        ok, msg = start_instance(iid)
        if not ok:
            return jsonify({"warning": f"created but failed to start: {msg}", "instance": public_view(iid)}), 201

    return jsonify({"instance": public_view(iid)}), 201


@app.post("/api/instances/<iid>/start")
def api_start(iid: str):
    if iid not in instances:
        return jsonify({"error": "no such instance"}), 404
    ok, msg = start_instance(iid)
    status = 200 if ok else 409
    return jsonify({"ok": ok, "message": msg, "instance": public_view(iid)}), status


@app.post("/api/instances/<iid>/stop")
def api_stop(iid: str):
    if iid not in instances:
        return jsonify({"error": "no such instance"}), 404
    ok, msg = stop_instance(iid)
    return jsonify({"ok": ok, "message": msg, "instance": public_view(iid)}), 200


@app.delete("/api/instances/<iid>")
def api_delete(iid: str):
    if iid not in instances:
        return jsonify({"error": "no such instance"}), 404

    for hmi_id in list(get_hmi_ids_for_plc(iid)):
        delete_hmi(hmi_id)

    stop_instance(iid)
    log_path = LOG_DIR / f"{iid}.log"
    if log_path.exists():
        log_path.unlink()
    del instances[iid]
    save_registry()
    return jsonify({"ok": True, "cascade": "attached HMI stopped and removed"}), 200


@app.get("/api/instances/<iid>/logs")
def api_logs(iid: str):
    if iid not in instances:
        return jsonify({"error": "no such instance"}), 404
    lines = request.args.get("lines", default=200, type=int)
    return jsonify({"log": tail_log(iid, lines)})


@app.post("/api/instances/<iid>/hmi")
def api_open_hmi(iid: str):
    if iid not in instances:
        return jsonify({"error": "no such instance"}), 404
    plc_cfg = instances[iid]
    if plc_cfg["protocol"] not in SUPPORTED_HMI_PROTOCOLS:
        return jsonify({"error": f"HMI client support for protocol '{plc_cfg['protocol']}' is not implemented"}), 501

    body = request.get_json(force=True, silent=True) or {}
    poll_interval = body.get("poll_interval", 1.0)
    try:
        poll_interval = max(0.2, float(poll_interval))
    except (TypeError, ValueError):
        return jsonify({"error": "poll_interval must be numeric"}), 400

    hmi_id = get_hmi_id_for_plc(iid)
    created = False
    if hmi_id is None:
        hmi_id = uuid.uuid4().hex[:8]
        hmis[hmi_id] = {
            "plc_id": iid,
            "name": f"{plc_cfg['name']} HMI",
            "host": plc_cfg["host"],
            "port": plc_cfg["port"],
            "protocol": plc_cfg["protocol"],
            "unit_id": plc_cfg["unit_id"],
            "vendor": plc_cfg["vendor"],
            "model": plc_cfg["model"],
            "product_code": plc_cfg["product_code"],
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
        sync_hmi_target_from_plc(hmis[hmi_id], plc_cfg)

    save_registry()
    ok, msg = start_hmi(hmi_id)
    if not ok and msg != "already running":
        return jsonify({"error": msg}), 409

    payload = {
        "ok": True,
        "message": "created" if created else msg,
        "hmi": public_hmi_view(hmi_id),
        "status": read_hmi_status(hmi_id),
    }
    return jsonify(payload), (201 if created else 200)


@app.post("/api/hmi/<hmi_id>/stop")
def api_hmi_stop(hmi_id: str):
    if hmi_id not in hmis:
        return jsonify({"error": "no such hmi"}), 404
    ok, msg = stop_hmi(hmi_id)
    return jsonify({"ok": ok, "message": msg, "hmi": public_hmi_view(hmi_id)}), 200


@app.delete("/api/hmi/<hmi_id>")
def api_hmi_delete(hmi_id: str):
    if hmi_id not in hmis:
        return jsonify({"error": "no such hmi"}), 404
    delete_hmi(hmi_id)
    return jsonify({"ok": True}), 200


@app.get("/api/hmi/<hmi_id>/status")
def api_hmi_status(hmi_id: str):
    if hmi_id not in hmis:
        return jsonify({"error": "no such hmi"}), 404
    return jsonify({"hmi": public_hmi_view(hmi_id), "status": read_hmi_status(hmi_id)})


@app.post("/api/hmi/<hmi_id>/command")
def api_hmi_command(hmi_id: str):
    if hmi_id not in hmis:
        return jsonify({"error": "no such hmi"}), 404
    if not public_hmi_view(hmi_id)["running"]:
        return jsonify({"error": "hmi is not running"}), 409

    body = request.get_json(force=True, silent=True) or {}
    action = str(body.get("action") or "").strip()
    if action not in {"set_pump", "set_valve", "set_setpoint"}:
        return jsonify({"error": "unsupported action"}), 400
    value = body.get("value")

    command_id = append_hmi_command(hmi_id, action, value)
    return jsonify({"ok": True, "command_id": command_id, "hmi": public_hmi_view(hmi_id)}), 202


@app.get("/api/authbind-status")
def api_authbind_status():
    return jsonify({"available": shutil.which("authbind") is not None})


@app.get("/")
def index():
    return send_from_directory(str(BASE_DIR / "templates"), "index.html")


def parse_args():
    parser = argparse.ArgumentParser(description="Web control panel for PLC emulator fleet")
    parser.add_argument("--host", default="127.0.0.1", help="Address the WEB UI itself binds to")
    parser.add_argument("--port", type=int, default=8080, help="Port the web UI binds to")
    parser.add_argument("--debug", action="store_true", help="Run Flask in debug/reload mode")
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()
    load_registry()
    app.run(host=args.host, port=args.port, debug=args.debug)

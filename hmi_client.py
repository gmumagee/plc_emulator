#!/usr/bin/env python3
"""Protocol-aware HMI client simulator for generic device definitions."""

from __future__ import annotations

import argparse
import contextlib
import json
import logging
import time
import uuid
from collections import deque
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import snap7
from pymodbus.client import ModbusTcpClient

from device_defs import DeviceDefinition, PointDefinition, engineering_to_raw, find_device_by_signature, load_device_definitions, raw_to_engineering
from emulator_core import build_s7_layout, get_bit, get_u16, set_bit, set_u16


log = logging.getLogger("hmi_client")
SUPPORTED_HMI_PROTOCOLS = {"modbus", "s7comm"}
MODBUS_KIND_TO_FUNC = {
    "coil": "read_coils",
    "discrete_input": "read_discrete_inputs",
    "holding_register": "read_holding_registers",
    "input_register": "read_input_registers",
}
S7_DB_PROCESS = 1
S7_DB_CONTROL = 2


@dataclass(frozen=True)
class HmiConfig:
    hmi_id: str
    device_id: str
    name: str
    host: str
    port: int
    protocol: str
    unit_id: int
    vendor: str
    model: str
    product_code: str
    poll_interval: float
    status_file: Path
    command_file: Path
    verbose: bool
    device_type: str | None = None
    device: DeviceDefinition | None = None


class CommandQueue:
    def __init__(self, path: Path):
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.touch(exist_ok=True)
        self.offset = self.path.stat().st_size

    def read_pending(self) -> list[dict[str, Any]]:
        commands: list[dict[str, Any]] = []
        with self.path.open("r", encoding="utf-8") as handle:
            handle.seek(self.offset)
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                try:
                    commands.append(json.loads(line))
                except json.JSONDecodeError:
                    log.warning("Skipping malformed command line: %r", line)
            self.offset = handle.tell()
        return commands


class StatusWriter:
    def __init__(self, path: Path):
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def write(self, payload: dict[str, Any]) -> None:
        tmp_path = self.path.with_suffix(self.path.suffix + ".tmp")
        tmp_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        tmp_path.replace(self.path)


def group_contiguous_points(points: list[PointDefinition]) -> list[list[PointDefinition]]:
    if not points:
        return []
    ordered = sorted(points, key=lambda point: point.address)
    groups: list[list[PointDefinition]] = [[ordered[0]]]
    for point in ordered[1:]:
        current_group = groups[-1]
        if point.address == current_group[-1].address + 1:
            current_group.append(point)
        else:
            groups.append([point])
    return groups


def snapshot_from_raw(device: DeviceDefinition, raw_values: dict[str, int]) -> dict[str, dict[str, Any]]:
    payload: dict[str, dict[str, Any]] = {}
    for point in device.points:
        raw_value = int(raw_values.get(point.id, 0))
        payload[point.id] = {
            "label": point.label,
            "kind": point.kind,
            "access": point.access,
            "unit": point.unit,
            "raw": raw_value,
            "value": raw_to_engineering(point, raw_value),
            "hmi": point.hmi,
        }
    return payload


class BaseHmiClient:
    unsupported_reason: str | None = None

    def __init__(self, config: HmiConfig):
        self.config = config
        if config.device is None:
            raise ValueError("HMI client requires a device definition")
        self.device = config.device

    def poll(self) -> dict[str, int]:
        raise NotImplementedError

    def execute(self, point_id: str, value: Any) -> None:
        raise NotImplementedError

    def close(self) -> None:
        return None


class UnsupportedHmiClient(BaseHmiClient):
    def __init__(self, config: HmiConfig, reason: str):
        super().__init__(config)
        self.unsupported_reason = reason

    def poll(self) -> dict[str, int]:
        raise RuntimeError(self.unsupported_reason or "unsupported protocol")

    def execute(self, point_id: str, value: Any) -> None:
        raise RuntimeError(self.unsupported_reason or "unsupported protocol")


class ModbusHmiClient(BaseHmiClient):
    def __init__(self, config: HmiConfig):
        super().__init__(config)
        self.client = ModbusTcpClient(config.host, port=config.port)
        self.connected = False

    def _ensure_connected(self) -> None:
        if self.connected:
            return
        self.connected = bool(self.client.connect())
        if not self.connected:
            raise ConnectionError(f"modbus connect failed to {self.config.host}:{self.config.port}")
        log.info("[%s] Connected Modbus client to %s:%d", self.config.hmi_id, self.config.host, self.config.port)

    def _check_response(self, response, action: str):
        if response.isError():
            raise RuntimeError(f"{action} failed: {response}")
        return response

    def poll(self) -> dict[str, int]:
        self._ensure_connected()
        raw_values: dict[str, int] = {}
        for kind in ("coil", "discrete_input", "holding_register", "input_register"):
            points = [point for point in self.device.points if point.kind == kind]
            for group in group_contiguous_points(points):
                start = group[0].address
                count = len(group)
                method_name = MODBUS_KIND_TO_FUNC[kind]
                response = self._check_response(
                    getattr(self.client, method_name)(start, count=count, slave=self.config.unit_id),
                    f"{method_name}({start}, count={count})",
                )
                values = response.bits if kind in {"coil", "discrete_input"} else response.registers
                for offset, point in enumerate(group):
                    raw_values[point.id] = int(values[offset])
        return raw_values

    def execute(self, point_id: str, value: Any) -> None:
        self._ensure_connected()
        point = self.device.point_by_id(point_id)
        if point is None or not point.writable:
            raise ValueError(f"point '{point_id}' is not writable on this device")
        if point.kind == "coil":
            self._check_response(
                self.client.write_coil(point.address, bool(value), slave=self.config.unit_id),
                f"write coil {point.address}",
            )
            return
        if point.kind == "holding_register":
            raw_value = engineering_to_raw(point, value)
            self._check_response(
                self.client.write_register(point.address, raw_value, slave=self.config.unit_id),
                f"write holding register {point.address}",
            )
            return
        raise ValueError(f"point '{point_id}' kind '{point.kind}' is not writable over Modbus")

    def close(self) -> None:
        with contextlib.suppress(Exception):
            self.client.close()
        self.connected = False


class S7HmiClient(BaseHmiClient):
    def __init__(self, config: HmiConfig):
        super().__init__(config)
        self.client = snap7.Client()
        self.connected = False
        self.layout = build_s7_layout(self.device)

    def _ensure_connected(self) -> None:
        if self.connected:
            return
        self.client.connect(self.config.host, 0, 0, tcp_port=self.config.port)
        self.connected = True
        log.info("[%s] Connected S7 client to %s:%d", self.config.hmi_id, self.config.host, self.config.port)

    def poll(self) -> dict[str, int]:
        self._ensure_connected()
        process_db = self.client.db_read(S7_DB_PROCESS, 0, self.layout.process_size)
        control_db = self.client.db_read(S7_DB_CONTROL, 0, self.layout.control_size)
        raw_values: dict[str, int] = {}
        for point in self.device.points:
            if point.kind == "coil":
                raw_values[point.id] = get_bit(control_db, point.address // 8, point.address % 8)
            elif point.kind == "holding_register":
                raw_values[point.id] = get_u16(control_db, self.layout.control_register_base + (point.address * 2))
            elif point.kind == "input_register":
                raw_values[point.id] = get_u16(process_db, point.address * 2)
            elif point.kind == "discrete_input":
                offset = self.layout.process_discrete_base + (point.address // 8)
                raw_values[point.id] = get_bit(process_db, offset, point.address % 8)
        return raw_values

    def execute(self, point_id: str, value: Any) -> None:
        self._ensure_connected()
        point = self.device.point_by_id(point_id)
        if point is None or not point.writable:
            raise ValueError(f"point '{point_id}' is not writable on this device")
        if point.kind == "coil":
            control_byte = bytearray(1)
            if point.address // 8 == 0:
                current = self.client.db_read(S7_DB_CONTROL, 0, 1)
                control_byte[:] = current[:1]
            set_bit(control_byte, 0, point.address % 8, 1 if value else 0)
            self.client.db_write(S7_DB_CONTROL, point.address // 8, control_byte)
            return
        if point.kind == "holding_register":
            raw_value = engineering_to_raw(point, value)
            data = bytearray(2)
            set_u16(data, 0, raw_value)
            self.client.db_write(S7_DB_CONTROL, self.layout.control_register_base + (point.address * 2), data)
            return
        raise ValueError(f"point '{point_id}' kind '{point.kind}' is not writable over S7")

    def close(self) -> None:
        with contextlib.suppress(Exception):
            self.client.disconnect()
        with contextlib.suppress(Exception):
            self.client.destroy()
        self.client = snap7.Client()
        self.connected = False


def build_client(config: HmiConfig) -> BaseHmiClient:
    if config.protocol == "modbus":
        return ModbusHmiClient(config)
    if config.protocol == "s7comm":
        return S7HmiClient(config)
    return UnsupportedHmiClient(
        config,
        f"HMI client support for protocol '{config.protocol}' is not implemented in this build.",
    )


def resolve_device(config_args: argparse.Namespace) -> DeviceDefinition:
    devices, errors = load_device_definitions()
    device_type = config_args.device_type or config_args.plc_type
    device = None
    if device_type:
        device = devices.get(device_type)
        if device is None:
            raise SystemExit(f"unknown device_type '{device_type}'")
    else:
        device = find_device_by_signature(devices, config_args.vendor, config_args.model, config_args.protocol)
    if device is None:
        detail = "; ".join(f"{error.file}: {error.error}" for error in errors) if errors else "no valid device definitions found"
        raise SystemExit(f"unable to resolve HMI device definition: {detail}")
    return device


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run a simulated HMI against a device emulator.")
    parser.add_argument("--hmi-id", required=True)
    parser.add_argument("--device-id", required=True)
    parser.add_argument("--device-type", default=None)
    parser.add_argument("--plc-type", default=None, help="Legacy alias for --device-type")
    parser.add_argument("--name", required=True)
    parser.add_argument("--host", required=True)
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--protocol", required=True)
    parser.add_argument("--unit-id", type=int, default=1)
    parser.add_argument("--vendor", default="")
    parser.add_argument("--model", default="")
    parser.add_argument("--product-code", default="")
    parser.add_argument("--poll-interval", type=float, default=1.0)
    parser.add_argument("--status-file", required=True)
    parser.add_argument("--command-file", required=True)
    parser.add_argument("-v", "--verbose", action="store_true")
    return parser.parse_args()


def add_event(events: deque[dict[str, Any]], event_type: str, message: str, **extra: Any) -> None:
    entry = {"ts": time.time(), "type": event_type, "message": message}
    entry.update(extra)
    events.append(entry)


def build_status_payload(
    config: HmiConfig,
    *,
    state: str,
    connected: bool,
    error: str | None,
    snapshot: dict[str, Any] | None,
    events: deque[dict[str, Any]],
    last_poll_ts: float | None,
    last_command_id: str | None,
    unsupported: bool,
) -> dict[str, Any]:
    return {
        "hmi_id": config.hmi_id,
        "device_id": config.device_id,
        "device_type": config.device_type,
        "protocol": config.protocol,
        "target": {
            "host": config.host,
            "port": config.port,
            "unit_id": config.unit_id,
            "vendor": config.vendor,
            "model": config.model,
        },
        "state": state,
        "connected": connected,
        "unsupported": unsupported,
        "error": error,
        "snapshot": snapshot,
        "recent_events": list(events),
        "last_poll_ts": last_poll_ts,
        "last_command_id": last_command_id,
        "updated_at": time.time(),
    }


def main() -> None:
    args = parse_args()
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)-7s %(message)s",
    )
    device = resolve_device(args)
    config = HmiConfig(
        hmi_id=args.hmi_id,
        device_id=args.device_id,
        name=args.name,
        host=args.host,
        port=args.port,
        protocol=args.protocol,
        unit_id=args.unit_id,
        vendor=args.vendor,
        model=args.model,
        product_code=args.product_code,
        poll_interval=max(0.2, float(args.poll_interval)),
        status_file=Path(args.status_file),
        command_file=Path(args.command_file),
        verbose=args.verbose,
        device_type=device.id,
        device=device,
    )

    queue = CommandQueue(config.command_file)
    writer = StatusWriter(config.status_file)
    events: deque[dict[str, Any]] = deque(maxlen=48)
    client = build_client(config)
    snapshot: dict[str, Any] | None = None
    error: str | None = None
    connected = False
    state = "starting"
    last_poll_ts: float | None = None
    last_command_id: str | None = None
    unsupported = client.unsupported_reason is not None
    next_poll_due = time.monotonic()

    if unsupported:
        error = client.unsupported_reason
        state = "unsupported"
        add_event(events, "error", error or "Unsupported protocol")
        log.error("[%s] %s", config.hmi_id, error)

    try:
        while True:
            for command in queue.read_pending():
                command_id = str(command.get("id") or uuid.uuid4().hex[:8])
                point_id = str(command.get("point_id") or "")
                value = command.get("value")
                try:
                    client.execute(point_id, value)
                    last_command_id = command_id
                    connected = not unsupported
                    state = "connected" if not unsupported else "unsupported"
                    if not unsupported:
                        error = None
                    add_event(events, "command", f"Command {point_id}={value!r} sent", command_id=command_id, point_id=point_id, value=value)
                    log.info("[%s] COMMAND point=%s value=%r", config.hmi_id, point_id, value)
                except Exception as exc:
                    connected = False
                    state = "degraded" if not unsupported else "unsupported"
                    error = str(exc)
                    add_event(events, "error", f"Command {point_id} failed: {exc}", command_id=command_id, point_id=point_id, value=value)
                    log.warning("[%s] COMMAND point=%s failed: %s", config.hmi_id, point_id, exc)
                    client.close()

            now = time.monotonic()
            if not unsupported and now >= next_poll_due:
                try:
                    raw_values = client.poll()
                    snapshot = {"points": snapshot_from_raw(device, raw_values)}
                    last_poll_ts = time.time()
                    connected = True
                    state = "connected"
                    error = None
                    add_event(events, "poll", f"Poll received {len(raw_values)} point values")
                    log.info("[%s] POLL received %d points", config.hmi_id, len(raw_values))
                except Exception as exc:
                    connected = False
                    state = "degraded"
                    error = str(exc)
                    add_event(events, "error", f"Poll failed: {exc}")
                    log.warning("[%s] POLL failed: %s", config.hmi_id, exc)
                    client.close()
                next_poll_due = now + config.poll_interval

            writer.write(
                build_status_payload(
                    config,
                    state=state,
                    connected=connected,
                    error=error,
                    snapshot=snapshot,
                    events=events,
                    last_poll_ts=last_poll_ts,
                    last_command_id=last_command_id,
                    unsupported=unsupported,
                )
            )
            time.sleep(0.1)
    except KeyboardInterrupt:
        log.info("[%s] HMI interrupted", config.hmi_id)
    finally:
        client.close()


if __name__ == "__main__":
    main()

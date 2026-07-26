#!/usr/bin/env python3
"""Shared device runtime, scaling, and simulation helpers."""

from __future__ import annotations

import argparse
import asyncio
import json
import random
import struct
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from device_defs import (
    BOOL_POINT_KINDS,
    DeviceDefinition,
    PointDefinition,
    engineering_to_raw,
    find_device_by_signature,
    load_device_definitions,
    raw_to_engineering,
)


def get_u16(buf: bytearray, offset: int) -> int:
    return struct.unpack_from(">H", bytes(buf), offset)[0]


def set_u16(buf: bytearray, offset: int, value: int) -> None:
    struct.pack_into(">H", buf, offset, max(0, min(0xFFFF, int(value))))


def get_bit(buf: bytearray, byte_offset: int, bit: int) -> int:
    return 1 if buf[byte_offset] & (1 << bit) else 0


def set_bit(buf: bytearray, byte_offset: int, bit: int, value: int) -> None:
    if value:
        buf[byte_offset] |= 1 << bit
    else:
        buf[byte_offset] &= ~(1 << bit)


def _align_even(value: int) -> int:
    return value if value % 2 == 0 else value + 1


@dataclass(frozen=True)
class S7Layout:
    process_input_bytes: int
    process_discrete_base: int
    process_size: int
    control_coil_bytes: int
    control_register_base: int
    control_size: int


def build_s7_layout(device: DeviceDefinition) -> S7Layout:
    max_input_reg = max((point.address for point in device.points if point.kind == "input_register"), default=-1)
    max_discrete = max((point.address for point in device.points if point.kind == "discrete_input"), default=-1)
    max_coil = max((point.address for point in device.points if point.kind == "coil"), default=-1)
    max_holding = max((point.address for point in device.points if point.kind == "holding_register"), default=-1)

    process_input_bytes = max(0, (max_input_reg + 1) * 2)
    process_discrete_base = _align_even(process_input_bytes)
    process_discrete_bytes = 0 if max_discrete < 0 else (max_discrete // 8) + 1
    process_size = max(process_input_bytes, process_discrete_base + process_discrete_bytes)

    control_coil_bytes = 0 if max_coil < 0 else (max_coil // 8) + 1
    control_register_base = _align_even(control_coil_bytes)
    control_register_bytes = max(0, (max_holding + 1) * 2)
    control_size = max(control_coil_bytes, control_register_base + control_register_bytes)

    return S7Layout(
        process_input_bytes=process_input_bytes,
        process_discrete_base=process_discrete_base,
        process_size=max(process_size, 2),
        control_coil_bytes=max(control_coil_bytes, 1),
        control_register_base=control_register_base,
        control_size=max(control_size, 2),
    )


@dataclass
class EmulatorConfig:
    host: str
    port: int
    protocol: str
    unit_id: int
    name: str
    vendor: str
    model: str
    product_code: str
    verbose: bool
    device_type: str | None = None
    device: DeviceDefinition | None = None
    fault_command_file: Path | None = None
    fault_status_file: Path | None = None


@dataclass
class ActiveFault:
    point_id: str
    mode: str
    params: dict[str, Any]
    activated_at: float
    activated_monotonic: float
    state: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "point": self.point_id,
            "mode": self.mode,
            "params": dict(self.params),
            "activated_at": self.activated_at,
        }
        if self.state:
            payload["state"] = dict(self.state)
        return payload


class JsonlCommandQueue:
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
                    payload = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if isinstance(payload, dict):
                    commands.append(payload)
            self.offset = handle.tell()
        return commands


class JsonStatusWriter:
    def __init__(self, path: Path):
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def write(self, payload: dict[str, Any]) -> None:
        tmp_path = self.path.with_suffix(self.path.suffix + ".tmp")
        tmp_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        tmp_path.replace(self.path)


@dataclass
class ProcessImage:
    device: DeviceDefinition
    start_monotonic: float = field(default_factory=time.monotonic)
    lock: threading.RLock = field(default_factory=threading.RLock)
    state: dict[str, Any] = field(init=False)
    shadow_state: dict[str, Any] = field(init=False)
    active_faults: dict[str, ActiveFault] = field(init=False)
    rng: random.Random = field(default_factory=random.Random)
    s7_layout: S7Layout = field(init=False)
    points_by_id: dict[str, PointDefinition] = field(init=False)
    points_by_kind_address: dict[tuple[str, int], PointDefinition] = field(init=False)

    def __post_init__(self) -> None:
        self.s7_layout = build_s7_layout(self.device)
        self.points_by_id = {point.id: point for point in self.device.points}
        self.points_by_kind_address = {(point.kind, point.address): point for point in self.device.points}
        self.state = {}
        self.shadow_state = {}
        self.active_faults = {}
        for point in self.device.points:
            if point.initial is not None:
                if point.is_bool:
                    self.state[point.id] = bool(point.initial)
                else:
                    self.state[point.id] = float(point.initial)
            elif point.is_bool:
                self.state[point.id] = False
            else:
                self.state[point.id] = 0.0

    def uptime_seconds(self) -> int:
        return int(time.monotonic() - self.start_monotonic) & 0xFFFF

    def get_point_value(self, point_id: str, default: Any = 0) -> Any:
        return self.state.get(point_id, default)

    def _normalize_value_for_point(self, point: PointDefinition, value: Any) -> Any:
        if point.is_bool:
            return bool(value)
        numeric = float(value)
        if point.unit == "%":
            numeric = max(0.0, min(100.0, numeric))
        if point.id == "scan_time_ms":
            numeric = max(1.0, min(5000.0, numeric))
        return numeric

    def set_point_value(self, point_id: str, value: Any) -> None:
        if point_id not in self.points_by_id:
            return
        point = self.points_by_id[point_id]
        self.state[point_id] = self._normalize_value_for_point(point, value)

    def _exposed_base_value_unlocked(self, point: PointDefinition) -> Any:
        if point.id == "uptime":
            return self.uptime_seconds()
        if point.id in self.shadow_state:
            return self.shadow_state[point.id]
        return self.get_point_value(point.id)

    def _apply_fault_to_value_unlocked(self, point: PointDefinition, value: Any) -> Any:
        fault = self.active_faults.get(point.id)
        if fault is None:
            return value
        if fault.mode == "freeze":
            return fault.state.get("frozen_value", value)
        if fault.mode == "drift":
            if point.is_bool:
                return value
            elapsed = max(0.0, time.monotonic() - fault.activated_monotonic)
            rate = float(fault.params.get("drift_rate_per_sec", 0.05))
            direction = float(fault.params.get("direction", 1.0))
            drifted = float(value) + (rate * direction * elapsed)
            return self._normalize_value_for_point(point, drifted)
        if fault.mode == "noise":
            if point.is_bool:
                return value
            amplitude = abs(float(fault.params.get("amplitude", fault.params.get("noise_amplitude", 0.25))))
            noisy = float(value) + self.rng.uniform(-amplitude, amplitude)
            return self._normalize_value_for_point(point, noisy)
        return value

    def get_exposed_point_value(self, point_id: str, default: Any = 0) -> Any:
        point = self.points_by_id.get(point_id)
        if point is None:
            return default
        with self.lock:
            return self._apply_fault_to_value_unlocked(point, self._exposed_base_value_unlocked(point))

    def write_raw_point(self, point: PointDefinition, raw_value: Any) -> None:
        engineering_value = self._normalize_value_for_point(point, raw_to_engineering(point, raw_value))
        if point.writable:
            stuck_fault = self.active_faults.get(point.id)
            if stuck_fault is not None and stuck_fault.mode == "stuck_actuator":
                self.shadow_state[point.id] = engineering_value
                return
        self.state[point.id] = engineering_value
        self.shadow_state.pop(point.id, None)

    def read_raw_point(self, point: PointDefinition) -> int:
        return engineering_to_raw(point, self.get_exposed_point_value(point.id))

    def clear_fault(self, point_id: str) -> None:
        with self.lock:
            fault = self.active_faults.pop(point_id, None)
            if fault is not None and fault.mode == "stuck_actuator":
                self.shadow_state.pop(point_id, None)

    def set_fault(self, point_id: str, mode: str, params: dict[str, Any] | None = None) -> ActiveFault:
        point = self.points_by_id.get(point_id)
        if point is None:
            raise ValueError(f"point '{point_id}' does not exist on this device")
        if point.fault is None or mode not in point.fault.modes:
            raise ValueError(f"point '{point_id}' does not support fault mode '{mode}'")
        if mode in {"drift", "noise"} and point.is_bool:
            raise ValueError(f"fault mode '{mode}' requires a numeric point")
        if mode == "stuck_actuator" and not point.writable:
            raise ValueError("stuck_actuator can only be applied to writable points")

        merged_params = dict(point.fault.defaults)
        if params:
            merged_params.update(params)

        with self.lock:
            previous = self.active_faults.pop(point_id, None)
            if previous is not None and previous.mode == "stuck_actuator":
                self.shadow_state.pop(point_id, None)
            now_wall = time.time()
            now_mono = time.monotonic()
            state: dict[str, Any] = {}
            if mode == "freeze":
                frozen_value = self._apply_fault_to_value_unlocked(point, self._exposed_base_value_unlocked(point))
                state["frozen_value"] = self._normalize_value_for_point(point, frozen_value)
            fault = ActiveFault(
                point_id=point_id,
                mode=mode,
                params=merged_params,
                activated_at=now_wall,
                activated_monotonic=now_mono,
                state=state,
            )
            self.active_faults[point_id] = fault
            return fault

    def fault_status(self) -> list[dict[str, Any]]:
        with self.lock:
            faults = [fault.to_dict() for fault in self.active_faults.values()]
        faults.sort(key=lambda item: (item["point"], item["mode"]))
        return faults

    def snapshot(self) -> dict[str, dict[str, Any]]:
        with self.lock:
            payload: dict[str, dict[str, Any]] = {}
            for point in self.device.points:
                value = self._apply_fault_to_value_unlocked(point, self._exposed_base_value_unlocked(point))
                payload[point.id] = {
                    "label": point.label,
                    "kind": point.kind,
                    "access": point.access,
                    "unit": point.unit,
                    "raw": engineering_to_raw(point, value),
                    "value": bool(value) if point.is_bool else float(value),
                    "hmi": point.hmi,
                }
            return payload

    def _apply_static(self) -> None:
        return None

    def _apply_random_walk(self) -> None:
        point_bounds = self.device.simulation.params.get("point_bounds", {})
        for point in self.device.points:
            if point.is_bool or point.access != "ro":
                continue
            bounds = point_bounds.get(point.id)
            if not isinstance(bounds, dict):
                continue
            current = float(self.get_point_value(point.id))
            minimum = float(bounds.get("min", current))
            maximum = float(bounds.get("max", current))
            step = float(bounds.get("step", 0.5))
            candidate = current + self.rng.uniform(-step, step)
            self.set_point_value(point.id, max(minimum, min(maximum, candidate)))

    def _apply_tank_pump_valve(self) -> None:
        params = self.device.simulation.params
        level_id = params.get("level_point_id", "level")
        flow_id = params.get("flow_point_id", "flow")
        alarm_id = params.get("alarm_point_id", "alarms")
        pump_id = params.get("pump_point_id", "pump_run")
        valve_id = params.get("valve_point_id", "valve_open")
        speed_id = params.get("speed_point_id", "pump_speed")
        high_sw_id = params.get("high_switch_point_id", "level_high_sw")
        low_sw_id = params.get("low_switch_point_id", "level_low_sw")
        level_point = self.points_by_id.get(level_id)
        flow_point = self.points_by_id.get(flow_id)
        if level_point is None:
            return

        fill_rate = float(params.get("fill_rate", 8.0))
        drain_rate = float(params.get("drain_rate", 6.0))
        raw_min = float(params.get("raw_min", 0.0))
        raw_max = float(params.get("raw_max", 1000.0))
        high_threshold = float(params.get("high_threshold", 900.0))
        low_threshold = float(params.get("low_threshold", 100.0))

        pump_run = bool(self.get_point_value(pump_id))
        valve_open = bool(self.get_point_value(valve_id))
        pump_speed = float(self.get_point_value(speed_id, 50.0))
        flow_in_raw = (max(0.0, min(100.0, pump_speed)) / 100.0) * fill_rate if pump_run else 0.0
        flow_out_raw = drain_rate if valve_open else 0.0

        current_level_raw = float(engineering_to_raw(level_point, self.get_point_value(level_id, 0.0)))
        next_level_raw = max(raw_min, min(raw_max, current_level_raw + flow_in_raw - flow_out_raw))
        self.set_point_value(level_id, raw_to_engineering(level_point, next_level_raw))

        if flow_point is not None:
            self.set_point_value(flow_id, raw_to_engineering(flow_point, flow_in_raw))

        level_high = next_level_raw >= high_threshold
        level_low = next_level_raw <= low_threshold
        if high_sw_id in self.points_by_id:
            self.set_point_value(high_sw_id, level_high)
        if low_sw_id in self.points_by_id:
            self.set_point_value(low_sw_id, level_low)
        if alarm_id in self.points_by_id:
            e_stop = bool(self.get_point_value("e_stop"))
            alarm_raw = (1 if level_high else 0) | ((1 if level_low else 0) << 1) | ((1 if e_stop else 0) << 2)
            self.set_point_value(alarm_id, raw_to_engineering(self.points_by_id[alarm_id], alarm_raw))
        if "alarm_ack" in self.points_by_id and self.get_point_value("alarm_ack"):
            self.set_point_value("alarm_ack", False)

    def _apply_actuator_feedback(self) -> None:
        params = self.device.simulation.params
        run_id = params.get("run_point_id", "pump_run")
        speed_id = params.get("speed_point_id", "pump_speed")
        flow_id = params.get("flow_point_id", "flow_rate")
        status_id = params.get("status_point_id", "motor_status")
        max_flow = float(params.get("max_flow", 10.0))
        status_run_bit = int(params.get("status_run_bit", 0))
        status_fault_bit = int(params.get("status_fault_bit", 1))

        pump_run = bool(self.get_point_value(run_id))
        pump_speed = float(self.get_point_value(speed_id, 100.0))
        if flow_id in self.points_by_id:
            flow_point = self.points_by_id[flow_id]
            flow_raw = (max(0.0, min(100.0, pump_speed)) / 100.0) * max_flow if pump_run else 0.0
            self.set_point_value(flow_id, raw_to_engineering(flow_point, flow_raw))
        if status_id in self.points_by_id:
            status_point = self.points_by_id[status_id]
            raw_status = (1 << status_run_bit) if pump_run else 0
            if params.get("fault", False):
                raw_status |= 1 << status_fault_bit
            self.set_point_value(status_id, raw_to_engineering(status_point, raw_status))

    def apply_physics_tick(self) -> None:
        with self.lock:
            sim_type = self.device.simulation.type
            if sim_type == "static":
                self._apply_static()
            elif sim_type == "random_walk":
                self._apply_random_walk()
            elif sim_type == "tank_pump_valve":
                self._apply_tank_pump_valve()
            elif sim_type == "actuator_feedback":
                self._apply_actuator_feedback()

    def read_modbus(self, fx: int, address: int, count: int = 1) -> list[int]:
        fx_map = {1: "coil", 2: "discrete_input", 3: "holding_register", 4: "input_register"}
        kind = fx_map.get(fx)
        values: list[int] = []
        if kind is None:
            return [0] * count
        with self.lock:
            for offset in range(count):
                point = self.points_by_kind_address.get((kind, address + offset))
                values.append(self.read_raw_point(point) if point else 0)
        return values

    def apply_modbus_write(self, fx: int, address: int, values: list[int]) -> None:
        if fx in (5, 15):
            kind = "coil"
        elif fx in (6, 16):
            kind = "holding_register"
        else:
            return
        with self.lock:
            for offset, raw_value in enumerate(values):
                point = self.points_by_kind_address.get((kind, address + offset))
                if point is None or not point.writable:
                    continue
                self.write_raw_point(point, raw_value)

    def sync_from_s7_controls(self, control_db: bytearray) -> None:
        with self.lock:
            for point in self.device.points:
                if not point.writable:
                    continue
                if point.kind == "coil":
                    byte_offset = point.address // 8
                    bit = point.address % 8
                    self.write_raw_point(point, get_bit(control_db, byte_offset, bit))
                elif point.kind == "holding_register":
                    offset = self.s7_layout.control_register_base + (point.address * 2)
                    self.write_raw_point(point, get_u16(control_db, offset))

    def sync_to_s7(self, process_db: bytearray, control_db: bytearray, engineering_db: bytearray) -> None:
        with self.lock:
            process_db[:] = b"\x00" * len(process_db)
            control_db[:] = b"\x00" * len(control_db)
            for point in self.device.points:
                raw_value = self.read_raw_point(point)
                if point.kind == "coil":
                    byte_offset = point.address // 8
                    bit = point.address % 8
                    set_bit(control_db, byte_offset, bit, raw_value)
                elif point.kind == "holding_register":
                    offset = self.s7_layout.control_register_base + (point.address * 2)
                    set_u16(control_db, offset, raw_value)
                elif point.kind == "input_register":
                    offset = point.address * 2
                    set_u16(process_db, offset, raw_value)
                elif point.kind == "discrete_input":
                    byte_offset = self.s7_layout.process_discrete_base + (point.address // 8)
                    bit = point.address % 8
                    set_bit(process_db, byte_offset, bit, raw_value)

            lines = [
                f"DEVICE={self.device.id}",
                f"SIMULATION={self.device.simulation.type}",
            ]
            for point in self.device.points:
                raw_value = self.read_raw_point(point)
                value = self.uptime_seconds() if point.id == "uptime" else self.get_point_value(point.id)
                lines.append(f"{point.id}: raw={raw_value} value={value}")
            blob = ("\n".join(lines) + "\n").encode("ascii", errors="ignore")
            engineering_db[:] = b"\x00" * len(engineering_db)
            engineering_db[: min(len(engineering_db), len(blob))] = blob[: len(engineering_db)]


async def run_physics(image: ProcessImage, tick_hz: float = 5.0) -> None:
    period = 1.0 / tick_hz
    while True:
        await asyncio.sleep(period)
        image.apply_physics_tick()


def resolve_device_preset(
    devices: dict[str, DeviceDefinition],
    device_type_key: str | None,
    vendor: str | None,
    model: str | None,
    protocol: str | None,
) -> DeviceDefinition | None:
    if device_type_key:
        return devices.get(device_type_key)
    return find_device_by_signature(devices, vendor, model, protocol)


def resolve_config_from_args(args: argparse.Namespace) -> EmulatorConfig:
    devices, errors = load_device_definitions()
    device_type_key = getattr(args, "device_type", None) or getattr(args, "plc_type", None)
    preset = resolve_device_preset(devices, device_type_key, args.vendor, args.model, args.protocol)
    default_preset = devices.get("generic-gc3000")
    resolved = preset or default_preset
    if resolved is None:
        detail = "; ".join(f"{error.file}: {error.error}" for error in errors) if errors else "no valid devices found"
        raise SystemExit(f"unable to resolve a device definition: {detail}")
    if device_type_key and preset is None:
        raise SystemExit(f"unknown device_type '{device_type_key}'")

    host = args.host
    port = args.port if args.port is not None else resolved.default_port
    protocol = args.protocol or resolved.protocol
    vendor = args.vendor or resolved.vendor
    model = args.model or resolved.model
    product_code = args.product_code or resolved.product_code

    return EmulatorConfig(
        host=host,
        port=port,
        protocol=protocol,
        unit_id=args.unit_id,
        name=args.name,
        vendor=vendor,
        model=model,
        product_code=product_code,
        verbose=args.verbose,
        device_type=device_type_key or resolved.id,
        device=resolved,
        fault_command_file=Path(args.fault_command_file) if getattr(args, "fault_command_file", None) else None,
        fault_status_file=Path(args.fault_status_file) if getattr(args, "fault_status_file", None) else None,
    )


async def run_fault_control(
    image: ProcessImage,
    *,
    command_file: Path | None,
    status_file: Path | None,
    tick_seconds: float = 0.2,
) -> None:
    queue = JsonlCommandQueue(command_file) if command_file is not None else None
    writer = JsonStatusWriter(status_file) if status_file is not None else None

    def write_status() -> None:
        if writer is None:
            return
        writer.write(
            {
                "updated_at": time.time(),
                "faults": image.fault_status(),
            }
        )

    write_status()
    while True:
        changed = False
        if queue is not None:
            for command in queue.read_pending():
                action = str(command.get("action") or "").strip()
                point_id = str(command.get("point") or "").strip()
                if not point_id:
                    continue
                if action == "set":
                    mode = str(command.get("mode") or "").strip()
                    if not mode:
                        continue
                    params = command.get("params", {})
                    if not isinstance(params, dict):
                        params = {}
                    image.set_fault(point_id, mode, params)
                    changed = True
                elif action == "clear":
                    image.clear_fault(point_id)
                    changed = True
        if changed:
            write_status()
        await asyncio.sleep(tick_seconds)

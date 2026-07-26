#!/usr/bin/env python3
"""Device definition schema and loader."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


DEVICE_DIR = Path(__file__).resolve().parent / "devices"
BOOL_POINT_KINDS = {"coil", "discrete_input"}
REGISTER_POINT_KINDS = {"holding_register", "input_register"}
SUPPORTED_POINT_KINDS = BOOL_POINT_KINDS | REGISTER_POINT_KINDS
SUPPORTED_POINT_ACCESS = {"ro", "rw"}
SUPPORTED_WIDGETS = {"toggle", "setpoint", "gauge", "readout", "alarm_bits"}
SUPPORTED_SIMULATION_TYPES = {"static", "random_walk", "tank_pump_valve", "actuator_feedback"}
SUPPORTED_FAULT_MODES = {"freeze", "drift", "noise", "stuck_actuator"}


@dataclass(frozen=True)
class SimulationDefinition:
    type: str
    params: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {"type": self.type, "params": dict(self.params)}


@dataclass(frozen=True)
class FaultDefinition:
    modes: tuple[str, ...]
    defaults: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {"modes": list(self.modes)}
        if self.defaults:
            payload["defaults"] = dict(self.defaults)
        return payload


@dataclass(frozen=True)
class PointDefinition:
    id: str
    label: str
    kind: str
    address: int
    access: str
    scale: float = 1.0
    unit: str | None = None
    initial: Any | None = None
    hmi: dict[str, Any] | None = None
    fault: FaultDefinition | None = None

    @property
    def is_bool(self) -> bool:
        return self.kind in BOOL_POINT_KINDS

    @property
    def writable(self) -> bool:
        return self.access == "rw"

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "id": self.id,
            "label": self.label,
            "kind": self.kind,
            "address": self.address,
            "access": self.access,
        }
        if self.scale != 1.0:
            payload["scale"] = self.scale
        if self.unit:
            payload["unit"] = self.unit
        if self.initial is not None:
            payload["initial"] = self.initial
        if self.hmi is not None:
            payload["hmi"] = self.hmi
        if self.fault is not None:
            payload["fault"] = self.fault.to_dict()
        return payload


@dataclass(frozen=True)
class DeviceDefinition:
    id: str
    vendor: str
    model: str
    device_class: str
    protocol: str
    default_port: int
    product_code: str
    simulation: SimulationDefinition
    points: tuple[PointDefinition, ...]
    source_file: Path

    @property
    def display_name(self) -> str:
        return f"{self.vendor} {self.model}"

    def point_by_id(self, point_id: str) -> PointDefinition | None:
        for point in self.points:
            if point.id == point_id:
                return point
        return None

    def points_for_hmi(self) -> list[PointDefinition]:
        return [point for point in self.points if point.hmi and point.hmi.get("widget") in SUPPORTED_WIDGETS]

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "vendor": self.vendor,
            "model": self.model,
            "display_name": self.display_name,
            "device_class": self.device_class,
            "protocol": self.protocol,
            "default_port": self.default_port,
            "product_code": self.product_code,
            "simulation": self.simulation.to_dict(),
            "points": [point.to_dict() for point in self.points],
        }


@dataclass(frozen=True)
class DeviceLoadError:
    file: str
    error: str

    def to_dict(self) -> dict[str, str]:
        return {"file": self.file, "error": self.error}


def _validate_simulation(payload: dict[str, Any], path: Path) -> SimulationDefinition:
    if not isinstance(payload, dict):
        raise ValueError(f"{path.name}: simulation must be an object")
    sim_type = payload.get("type")
    if not isinstance(sim_type, str) or not sim_type:
        raise ValueError(f"{path.name}: simulation.type is required")
    if sim_type not in SUPPORTED_SIMULATION_TYPES:
        raise ValueError(
            f"{path.name}: unsupported simulation.type '{sim_type}' "
            f"(expected one of {', '.join(sorted(SUPPORTED_SIMULATION_TYPES))})"
        )
    params = payload.get("params", {})
    if not isinstance(params, dict):
        raise ValueError(f"{path.name}: simulation.params must be an object")
    return SimulationDefinition(type=sim_type, params=params)


def _validate_hmi(payload: Any, path: Path, point_id: str) -> dict[str, Any] | None:
    if payload is None:
        return None
    if not isinstance(payload, dict):
        raise ValueError(f"{path.name}: point '{point_id}' hmi must be an object")
    widget = payload.get("widget")
    if not isinstance(widget, str) or widget not in SUPPORTED_WIDGETS:
        raise ValueError(
            f"{path.name}: point '{point_id}' hmi.widget must be one of "
            f"{', '.join(sorted(SUPPORTED_WIDGETS))}"
        )
    if widget == "alarm_bits":
        bits = payload.get("bits")
        if not isinstance(bits, list) or not bits:
            raise ValueError(f"{path.name}: point '{point_id}' alarm_bits widget requires a non-empty bits list")
        for entry in bits:
            if not isinstance(entry, dict):
                raise ValueError(f"{path.name}: point '{point_id}' alarm_bits entries must be objects")
            if not isinstance(entry.get("bit"), int) or entry["bit"] < 0:
                raise ValueError(f"{path.name}: point '{point_id}' alarm_bits entries need a non-negative integer bit")
            if not isinstance(entry.get("label"), str) or not entry["label"]:
                raise ValueError(f"{path.name}: point '{point_id}' alarm_bits entries need a label")
    return payload


def _validate_fault(payload: Any, path: Path, point_id: str) -> FaultDefinition | None:
    if payload is None:
        return None
    if not isinstance(payload, dict):
        raise ValueError(f"{path.name}: point '{point_id}' fault must be an object")
    modes = payload.get("modes")
    if not isinstance(modes, list) or not modes:
        raise ValueError(f"{path.name}: point '{point_id}' fault.modes must be a non-empty list")
    normalized_modes: list[str] = []
    for mode in modes:
        if not isinstance(mode, str) or mode not in SUPPORTED_FAULT_MODES:
            raise ValueError(
                f"{path.name}: point '{point_id}' fault mode must be one of "
                f"{', '.join(sorted(SUPPORTED_FAULT_MODES))}"
            )
        normalized_modes.append(mode)
    defaults = payload.get("defaults", {})
    if not isinstance(defaults, dict):
        raise ValueError(f"{path.name}: point '{point_id}' fault.defaults must be an object when present")
    return FaultDefinition(modes=tuple(normalized_modes), defaults=defaults)


def _validate_point(payload: Any, path: Path, seen_ids: set[str], seen_addresses: set[tuple[str, int]]) -> PointDefinition:
    if not isinstance(payload, dict):
        raise ValueError(f"{path.name}: points entries must be objects")
    point_id = payload.get("id")
    if not isinstance(point_id, str) or not point_id:
        raise ValueError(f"{path.name}: each point requires a non-empty string id")
    if point_id in seen_ids:
        raise ValueError(f"{path.name}: duplicate point id '{point_id}'")
    label = payload.get("label")
    if not isinstance(label, str) or not label:
        raise ValueError(f"{path.name}: point '{point_id}' requires a non-empty label")
    kind = payload.get("kind")
    if kind not in SUPPORTED_POINT_KINDS:
        raise ValueError(
            f"{path.name}: point '{point_id}' kind must be one of {', '.join(sorted(SUPPORTED_POINT_KINDS))}"
        )
    try:
        address = int(payload.get("address"))
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{path.name}: point '{point_id}' address must be an integer") from exc
    if address < 0:
        raise ValueError(f"{path.name}: point '{point_id}' address must be >= 0")
    access = payload.get("access")
    if access not in SUPPORTED_POINT_ACCESS:
        raise ValueError(f"{path.name}: point '{point_id}' access must be one of {', '.join(sorted(SUPPORTED_POINT_ACCESS))}")
    try:
        scale = float(payload.get("scale", 1.0))
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{path.name}: point '{point_id}' scale must be numeric") from exc
    if scale == 0:
        raise ValueError(f"{path.name}: point '{point_id}' scale cannot be zero")
    unit = payload.get("unit")
    if unit is not None and not isinstance(unit, str):
        raise ValueError(f"{path.name}: point '{point_id}' unit must be a string when present")
    hmi = _validate_hmi(payload.get("hmi"), path, point_id)
    fault = _validate_fault(payload.get("fault"), path, point_id)
    address_key = (kind, address)
    if address_key in seen_addresses:
        raise ValueError(f"{path.name}: duplicate {kind} address {address} across points")
    seen_ids.add(point_id)
    seen_addresses.add(address_key)
    return PointDefinition(
        id=point_id,
        label=label,
        kind=kind,
        address=address,
        access=access,
        scale=scale,
        unit=unit,
        initial=payload.get("initial"),
        hmi=hmi,
        fault=fault,
    )


def _validate_device(payload: Any, path: Path) -> DeviceDefinition:
    if not isinstance(payload, dict):
        raise ValueError(f"{path.name}: top-level JSON must be an object")

    required = ("id", "vendor", "model", "device_class", "protocol", "default_port", "product_code", "simulation", "points")
    missing = [field for field in required if field not in payload]
    if missing:
        raise ValueError(f"{path.name}: missing required fields: {', '.join(missing)}")

    device_id = payload["id"]
    if not isinstance(device_id, str) or not device_id:
        raise ValueError(f"{path.name}: id must be a non-empty string")
    vendor = payload["vendor"]
    model = payload["model"]
    device_class = payload["device_class"]
    protocol = payload["protocol"]
    product_code = payload["product_code"]
    for field_name, value in (
        ("vendor", vendor),
        ("model", model),
        ("device_class", device_class),
        ("protocol", protocol),
        ("product_code", product_code),
    ):
        if not isinstance(value, str) or not value:
            raise ValueError(f"{path.name}: {field_name} must be a non-empty string")

    try:
        default_port = int(payload["default_port"])
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{path.name}: default_port must be an integer") from exc
    if not (1 <= default_port <= 65535):
        raise ValueError(f"{path.name}: default_port must be between 1 and 65535")

    simulation = _validate_simulation(payload["simulation"], path)
    points_payload = payload["points"]
    if not isinstance(points_payload, list) or not points_payload:
        raise ValueError(f"{path.name}: points must be a non-empty list")
    seen_ids: set[str] = set()
    seen_addresses: set[tuple[str, int]] = set()
    points = tuple(_validate_point(point, path, seen_ids, seen_addresses) for point in points_payload)

    return DeviceDefinition(
        id=device_id,
        vendor=vendor,
        model=model,
        device_class=device_class,
        protocol=protocol,
        default_port=default_port,
        product_code=product_code,
        simulation=simulation,
        points=points,
        source_file=path,
    )


def load_device_definitions(device_dir: Path | None = None) -> tuple[dict[str, DeviceDefinition], list[DeviceLoadError]]:
    root = device_dir or DEVICE_DIR
    devices: dict[str, DeviceDefinition] = {}
    errors: list[DeviceLoadError] = []
    if not root.exists():
        return {}, [DeviceLoadError(file=str(root), error="device directory does not exist")]

    for path in sorted(root.glob("*.json")):
        try:
            payload = json.loads(path.read_text())
            device = _validate_device(payload, path)
            if device.id in devices:
                raise ValueError(f"duplicate device id '{device.id}' already loaded from {devices[device.id].source_file.name}")
            devices[device.id] = device
        except (OSError, json.JSONDecodeError, ValueError) as exc:
            errors.append(DeviceLoadError(file=path.name, error=str(exc)))
    return devices, errors


def load_valid_devices(device_dir: Path | None = None) -> dict[str, DeviceDefinition]:
    devices, _ = load_device_definitions(device_dir)
    return devices


def find_device_by_signature(
    devices: dict[str, DeviceDefinition],
    vendor: str | None,
    model: str | None,
    protocol: str | None = None,
) -> DeviceDefinition | None:
    if not vendor or not model:
        return None
    for device in devices.values():
        if device.vendor != vendor or device.model != model:
            continue
        if protocol and device.protocol != protocol:
            continue
        return device
    return None


def engineering_to_raw(point: PointDefinition, value: Any) -> int:
    if point.is_bool:
        return 1 if bool(value) else 0
    return int(round(float(value) / point.scale))


def raw_to_engineering(point: PointDefinition, raw_value: Any) -> Any:
    if point.is_bool:
        return bool(raw_value)
    return float(raw_value) * point.scale

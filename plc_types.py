#!/usr/bin/env python3
"""Shared PLC type registry loader for the web UI and emulator."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from pathlib import Path


PLC_TYPES_FILE = Path(__file__).resolve().parent / "plc_types.json"


@dataclass(frozen=True)
class PlcType:
    key: str
    vendor: str
    model: str
    protocol: str
    default_port: int
    product_code: str

    def to_dict(self) -> dict[str, object]:
        data = asdict(self)
        data.pop("key", None)
        return data


def _validate_entry(key: str, data: dict[str, object]) -> PlcType:
    required = ("vendor", "model", "protocol", "default_port", "product_code")
    missing = [field for field in required if field not in data]
    if missing:
        raise ValueError(f"plc_types.json entry '{key}' is missing required fields: {', '.join(missing)}")

    try:
        default_port = int(data["default_port"])
    except (TypeError, ValueError) as exc:
        raise ValueError(f"plc_types.json entry '{key}' has invalid default_port") from exc

    if not (1 <= default_port <= 65535):
        raise ValueError(f"plc_types.json entry '{key}' has out-of-range default_port {default_port}")

    return PlcType(
        key=key,
        vendor=str(data["vendor"]),
        model=str(data["model"]),
        protocol=str(data["protocol"]),
        default_port=default_port,
        product_code=str(data["product_code"]),
    )


def load_plc_types(path: Path | None = None) -> dict[str, PlcType]:
    registry_path = path or PLC_TYPES_FILE
    raw = json.loads(registry_path.read_text())
    return {key: _validate_entry(key, value) for key, value in raw.items()}


def load_plc_types_for_api(path: Path | None = None) -> dict[str, dict[str, object]]:
    return {key: plc_type.to_dict() for key, plc_type in load_plc_types(path).items()}


def find_plc_type_by_signature(
    plc_types: dict[str, PlcType],
    vendor: str | None,
    model: str | None,
    protocol: str | None = None,
) -> PlcType | None:
    if not vendor or not model:
        return None

    for plc_type in plc_types.values():
        if plc_type.vendor != vendor or plc_type.model != model:
            continue
        if protocol and plc_type.protocol != protocol:
            continue
        return plc_type
    return None

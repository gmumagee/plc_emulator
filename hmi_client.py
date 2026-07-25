#!/usr/bin/env python3
"""Protocol-aware HMI client simulator for PLC fleet exercises."""

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

from emulator_core import (
    CO_PUMP_RUN,
    CO_VALVE_OPEN,
    DI_LEVEL_HIGH,
    DI_LEVEL_LOW,
    HR_LEVEL_SP,
    HR_PUMP_SPEED_SP,
    IR_ALARM_WORD,
    IR_FLOW_RATE,
    IR_TANK_LEVEL,
    IR_UPTIME,
    get_bit,
    get_u16,
    set_bit,
    set_u16,
)


log = logging.getLogger("hmi_client")

SUPPORTED_HMI_PROTOCOLS = {"modbus", "s7comm"}
S7_DB_PROCESS = 1
S7_DB_CONTROL = 2
S7_PROCESS_READ_SIZE = 10
S7_CONTROL_READ_SIZE = 8


@dataclass(frozen=True)
class HmiConfig:
    hmi_id: str
    plc_id: str
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


class BaseHmiClient:
    unsupported_reason: str | None = None

    def __init__(self, config: HmiConfig):
        self.config = config

    def poll(self) -> dict[str, Any]:
        raise NotImplementedError

    def execute(self, action: str, value: Any) -> None:
        raise NotImplementedError

    def close(self) -> None:
        return None


class UnsupportedHmiClient(BaseHmiClient):
    def __init__(self, config: HmiConfig, reason: str):
        super().__init__(config)
        self.unsupported_reason = reason

    def poll(self) -> dict[str, Any]:
        raise RuntimeError(self.unsupported_reason or "unsupported protocol")

    def execute(self, action: str, value: Any) -> None:
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

    def poll(self) -> dict[str, Any]:
        self._ensure_connected()
        coils = self._check_response(
            self.client.read_coils(CO_PUMP_RUN, count=3, slave=self.config.unit_id),
            "read coils",
        ).bits
        discrete = self._check_response(
            self.client.read_discrete_inputs(DI_LEVEL_HIGH, count=3, slave=self.config.unit_id),
            "read discrete inputs",
        ).bits
        holding = self._check_response(
            self.client.read_holding_registers(HR_LEVEL_SP, count=3, slave=self.config.unit_id),
            "read holding registers",
        ).registers
        inputs = self._check_response(
            self.client.read_input_registers(IR_TANK_LEVEL, count=4, slave=self.config.unit_id),
            "read input registers",
        ).registers

        return {
            "tank_level_pct": inputs[IR_TANK_LEVEL] / 10.0,
            "flow_rate": inputs[IR_FLOW_RATE] / 10.0,
            "alarm_word": inputs[IR_ALARM_WORD],
            "uptime_s": inputs[IR_UPTIME],
            "pump_run": bool(coils[CO_PUMP_RUN]),
            "valve_open": bool(coils[CO_VALVE_OPEN]),
            "level_high": bool(discrete[DI_LEVEL_HIGH]),
            "level_low": bool(discrete[DI_LEVEL_LOW]),
            "level_setpoint_pct": holding[HR_LEVEL_SP] / 10.0,
            "pump_speed_pct": holding[HR_PUMP_SPEED_SP],
        }

    def execute(self, action: str, value: Any) -> None:
        self._ensure_connected()
        if action == "set_pump":
            self._check_response(
                self.client.write_coil(CO_PUMP_RUN, bool(value), slave=self.config.unit_id),
                "write pump coil",
            )
            return
        if action == "set_valve":
            self._check_response(
                self.client.write_coil(CO_VALVE_OPEN, bool(value), slave=self.config.unit_id),
                "write valve coil",
            )
            return
        if action == "set_setpoint":
            setpoint = max(0, min(1000, int(round(float(value) * 10))))
            self._check_response(
                self.client.write_register(HR_LEVEL_SP, setpoint, slave=self.config.unit_id),
                "write setpoint register",
            )
            return
        raise ValueError(f"unsupported action '{action}'")

    def close(self) -> None:
        with contextlib.suppress(Exception):
            self.client.close()
        self.connected = False


class S7HmiClient(BaseHmiClient):
    def __init__(self, config: HmiConfig):
        super().__init__(config)
        self.client = snap7.Client()
        self.connected = False

    def _ensure_connected(self) -> None:
        if self.connected:
            return
        self.client.connect(self.config.host, 0, 0, tcp_port=self.config.port)
        self.connected = True
        log.info("[%s] Connected S7 client to %s:%d", self.config.hmi_id, self.config.host, self.config.port)

    def _read_control(self) -> bytearray:
        return self.client.db_read(S7_DB_CONTROL, 0, S7_CONTROL_READ_SIZE)

    def poll(self) -> dict[str, Any]:
        self._ensure_connected()
        process_db = self.client.db_read(S7_DB_PROCESS, 0, S7_PROCESS_READ_SIZE)
        control_db = self.client.db_read(S7_DB_CONTROL, 0, S7_CONTROL_READ_SIZE)

        alarm_word = get_u16(process_db, 4)
        return {
            "tank_level_pct": get_u16(process_db, 0) / 10.0,
            "flow_rate": get_u16(process_db, 2) / 10.0,
            "alarm_word": alarm_word,
            "uptime_s": get_u16(process_db, 6),
            "pump_run": bool(get_bit(control_db, 0, 0)),
            "valve_open": bool(get_bit(control_db, 0, 1)),
            "level_high": bool(get_bit(process_db, 8, 0)),
            "level_low": bool(get_bit(process_db, 8, 1)),
            "level_setpoint_pct": get_u16(control_db, 2) / 10.0,
            "pump_speed_pct": get_u16(control_db, 4),
        }

    def execute(self, action: str, value: Any) -> None:
        self._ensure_connected()
        if action == "set_pump":
            control = self._read_control()
            set_bit(control, 0, 0, 1 if value else 0)
            self.client.db_write(S7_DB_CONTROL, 0, control[:1])
            return
        if action == "set_valve":
            control = self._read_control()
            set_bit(control, 0, 1, 1 if value else 0)
            self.client.db_write(S7_DB_CONTROL, 0, control[:1])
            return
        if action == "set_setpoint":
            value_u16 = bytearray(2)
            set_u16(value_u16, 0, max(0, min(1000, int(round(float(value) * 10)))))
            self.client.db_write(S7_DB_CONTROL, 2, value_u16)
            return
        raise ValueError(f"unsupported action '{action}'")

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


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run a simulated HMI against a PLC emulator.")
    parser.add_argument("--hmi-id", required=True)
    parser.add_argument("--plc-id", required=True)
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
    entry = {
        "ts": time.time(),
        "type": event_type,
        "message": message,
    }
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
        "plc_id": config.plc_id,
        "name": config.name,
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
    config = HmiConfig(
        hmi_id=args.hmi_id,
        plc_id=args.plc_id,
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
    )

    queue = CommandQueue(config.command_file)
    writer = StatusWriter(config.status_file)
    events: deque[dict[str, Any]] = deque(maxlen=32)
    client = build_client(config)
    snapshot: dict[str, Any] | None = None
    error: str | None = None
    connected = False
    state = "starting"
    last_poll_ts: float | None = None
    last_command_id: str | None = None
    unsupported = client.unsupported_reason is not None

    if unsupported:
        error = client.unsupported_reason
        state = "unsupported"
        add_event(events, "error", error or "Unsupported protocol")
        log.error("[%s] %s", config.hmi_id, error)

    next_poll_due = time.monotonic()

    try:
        while True:
            for command in queue.read_pending():
                command_id = str(command.get("id") or uuid.uuid4().hex[:8])
                action = str(command.get("action") or "")
                value = command.get("value")
                try:
                    client.execute(action, value)
                    last_command_id = command_id
                    connected = not unsupported
                    state = "connected" if not unsupported else "unsupported"
                    error = None if not unsupported else error
                    message = f"Command {action}={value!r} sent"
                    add_event(events, "command", message, command_id=command_id, action=action, value=value)
                    log.info("[%s] COMMAND %s value=%r", config.hmi_id, action, value)
                except Exception as exc:
                    connected = False
                    state = "degraded" if not unsupported else "unsupported"
                    error = str(exc)
                    add_event(
                        events,
                        "error",
                        f"Command {action} failed: {exc}",
                        command_id=command_id,
                        action=action,
                        value=value,
                    )
                    log.warning("[%s] COMMAND %s failed: %s", config.hmi_id, action, exc)
                    client.close()

            now = time.monotonic()
            if not unsupported and now >= next_poll_due:
                try:
                    snapshot = client.poll()
                    last_poll_ts = time.time()
                    connected = True
                    state = "connected"
                    error = None
                    add_event(
                        events,
                        "poll",
                        (
                            f"Poll level={snapshot['tank_level_pct']:.1f}% "
                            f"flow={snapshot['flow_rate']:.1f} "
                            f"pump={'ON' if snapshot['pump_run'] else 'OFF'} "
                            f"valve={'OPEN' if snapshot['valve_open'] else 'CLOSED'}"
                        ),
                    )
                    log.info(
                        "[%s] POLL level=%.1f flow=%.1f alarm=%s pump=%s valve=%s setpoint=%.1f",
                        config.hmi_id,
                        snapshot["tank_level_pct"],
                        snapshot["flow_rate"],
                        snapshot["alarm_word"],
                        snapshot["pump_run"],
                        snapshot["valve_open"],
                        snapshot["level_setpoint_pct"],
                    )
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

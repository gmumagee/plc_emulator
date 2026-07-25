#!/usr/bin/env python3
"""Shared process image and CLI resolution helpers for protocol backends."""

from __future__ import annotations

import argparse
import asyncio
import struct
import threading
import time
from dataclasses import dataclass, field

from plc_types import PlcType, find_plc_type_by_signature, load_plc_types


CO_PUMP_RUN, CO_VALVE_OPEN, CO_ALARM_ACK = 0, 1, 2
DI_LEVEL_HIGH, DI_LEVEL_LOW, DI_ESTOP = 0, 1, 2
HR_LEVEL_SP, HR_PUMP_SPEED_SP, HR_SCAN_TIME = 0, 1, 2
IR_TANK_LEVEL, IR_FLOW_RATE, IR_ALARM_WORD, IR_UPTIME = 0, 1, 2, 3


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
    plc_type: str | None = None


@dataclass
class ProcessImage:
    start_monotonic: float = field(default_factory=time.monotonic)
    lock: threading.RLock = field(default_factory=threading.RLock)
    level_x10: float = 300.0
    level_setpoint: int = 500
    pump_speed_setpoint: int = 50
    scan_time_ms: int = 100
    pump_run: int = 1
    valve_open: int = 0
    alarm_ack: int = 0
    level_high_sw: int = 0
    level_low_sw: int = 0
    e_stop: int = 0
    flow_rate_x10: int = 0
    alarm_word: int = 0

    def apply_physics_tick(self) -> None:
        with self.lock:
            flow_in = (self.pump_speed_setpoint / 100.0) * 8.0 if self.pump_run else 0.0
            flow_out = 6.0 if self.valve_open else 0.0

            self.level_x10 += flow_in - flow_out
            self.level_x10 = max(0.0, min(1000.0, self.level_x10))

            self.level_high_sw = 1 if self.level_x10 >= 900 else 0
            self.level_low_sw = 1 if self.level_x10 <= 100 else 0
            self.alarm_word = (self.level_high_sw << 0) | (self.level_low_sw << 1) | (self.e_stop << 2)
            self.flow_rate_x10 = int(flow_in * 10)

            if self.alarm_ack:
                self.alarm_ack = 0

    def uptime_seconds(self) -> int:
        return int(time.monotonic() - self.start_monotonic) & 0xFFFF

    def read_modbus(self, fx: int, address: int, count: int = 1) -> list[int]:
        values: list[int] = []
        with self.lock:
            for offset in range(count):
                current = address + offset
                if fx == 1:
                    mapping = {
                        CO_PUMP_RUN: self.pump_run,
                        CO_VALVE_OPEN: self.valve_open,
                        CO_ALARM_ACK: self.alarm_ack,
                    }
                    values.append(mapping.get(current, 0))
                elif fx == 2:
                    mapping = {
                        DI_LEVEL_HIGH: self.level_high_sw,
                        DI_LEVEL_LOW: self.level_low_sw,
                        DI_ESTOP: self.e_stop,
                    }
                    values.append(mapping.get(current, 0))
                elif fx == 3:
                    mapping = {
                        HR_LEVEL_SP: self.level_setpoint,
                        HR_PUMP_SPEED_SP: self.pump_speed_setpoint,
                        HR_SCAN_TIME: self.scan_time_ms,
                    }
                    values.append(mapping.get(current, 0))
                elif fx == 4:
                    mapping = {
                        IR_TANK_LEVEL: int(self.level_x10),
                        IR_FLOW_RATE: self.flow_rate_x10,
                        IR_ALARM_WORD: self.alarm_word,
                        IR_UPTIME: self.uptime_seconds(),
                    }
                    values.append(mapping.get(current, 0))
                else:
                    values.append(0)
        return values

    def apply_modbus_write(self, fx: int, address: int, values: list[int]) -> None:
        if fx in (5, 15):
            fx = 1
        elif fx in (6, 16):
            fx = 3
        with self.lock:
            for offset, raw_value in enumerate(values):
                current = address + offset
                value = int(raw_value)
                if fx == 1:
                    if current == CO_PUMP_RUN:
                        self.pump_run = 1 if value else 0
                    elif current == CO_VALVE_OPEN:
                        self.valve_open = 1 if value else 0
                    elif current == CO_ALARM_ACK:
                        self.alarm_ack = 1 if value else 0
                elif fx == 3:
                    if current == HR_LEVEL_SP:
                        self.level_setpoint = max(0, min(1000, value))
                    elif current == HR_PUMP_SPEED_SP:
                        self.pump_speed_setpoint = max(0, min(100, value))
                    elif current == HR_SCAN_TIME:
                        self.scan_time_ms = max(1, min(5000, value))

    def sync_from_s7_controls(self, control_db: bytearray) -> None:
        with self.lock:
            self.pump_run = get_bit(control_db, 0, 0)
            self.valve_open = get_bit(control_db, 0, 1)
            self.alarm_ack = get_bit(control_db, 0, 2)
            self.level_setpoint = max(0, min(1000, get_u16(control_db, 2)))
            self.pump_speed_setpoint = max(0, min(100, get_u16(control_db, 4)))
            self.scan_time_ms = max(1, min(5000, get_u16(control_db, 6)))

    def sync_to_s7(self, process_db: bytearray, control_db: bytearray, engineering_db: bytearray) -> None:
        with self.lock:
            set_u16(process_db, 0, int(self.level_x10))
            set_u16(process_db, 2, self.flow_rate_x10)
            set_u16(process_db, 4, self.alarm_word)
            set_u16(process_db, 6, self.uptime_seconds())
            set_bit(process_db, 8, 0, self.level_high_sw)
            set_bit(process_db, 8, 1, self.level_low_sw)
            set_bit(process_db, 8, 2, self.e_stop)

            set_bit(control_db, 0, 0, self.pump_run)
            set_bit(control_db, 0, 1, self.valve_open)
            set_bit(control_db, 0, 2, self.alarm_ack)
            set_u16(control_db, 2, self.level_setpoint)
            set_u16(control_db, 4, self.pump_speed_setpoint)
            set_u16(control_db, 6, self.scan_time_ms)

            header = (
                f"S7 ENGINEERING BLOCK\n"
                f"LEVEL_X10={int(self.level_x10)}\n"
                f"FLOW_X10={self.flow_rate_x10}\n"
                f"ALARM_WORD={self.alarm_word}\n"
                f"UPTIME={self.uptime_seconds()}\n"
            ).encode("ascii", errors="ignore")
            engineering_db[: len(header)] = header


async def run_physics(image: ProcessImage, tick_hz: float = 5.0) -> None:
    period = 1.0 / tick_hz
    while True:
        await asyncio.sleep(period)
        image.apply_physics_tick()


def resolve_plc_preset(
    plc_types: dict[str, PlcType],
    plc_type_key: str | None,
    vendor: str | None,
    model: str | None,
    protocol: str | None,
) -> PlcType | None:
    if plc_type_key:
        return plc_types.get(plc_type_key)
    return find_plc_type_by_signature(plc_types, vendor, model, protocol)


def resolve_config_from_args(args: argparse.Namespace) -> EmulatorConfig:
    plc_types = load_plc_types()
    preset = resolve_plc_preset(plc_types, args.plc_type, args.vendor, args.model, args.protocol)
    default_preset = plc_types.get("generic-gc3000")
    resolved = preset or default_preset
    if resolved is None:
        raise SystemExit("no default PLC type available in plc_types.json")

    host = args.host
    port = args.port if args.port is not None else resolved.default_port
    protocol = args.protocol or resolved.protocol
    vendor = args.vendor or resolved.vendor
    model = args.model or resolved.model
    product_code = args.product_code or resolved.product_code
    plc_type_key = args.plc_type or (resolved.key if preset else None)

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
        plc_type=plc_type_key,
    )

#!/usr/bin/env python3
"""
plc_emulator.py — A software PLC that speaks real Modbus/TCP on the wire.

Built for controlled ICS security lab / testbed use (isolated network segments
only). This isn't a toy that just returns zeros: it runs a small simulated
physical process (a tank with an inlet pump and outlet valve) in the
background, so register values actually move over time the way a real
controller's would, and every read/write coming in over the network is
logged.

Requires: pymodbus==3.8.6   (pip install pymodbus==3.8.6 --break-system-packages)
Pinned deliberately — pymodbus 3.9+ deprecates/breaks the synchronous
datastore API this script uses. 3.8.6 is stable and this is the API almost
all Modbus-simulator tutorials and examples are written against.

--------------------------------------------------------------------------
Modbus memory map exposed by this emulator (unit/slave id = 1)
--------------------------------------------------------------------------
Coils (read/write bits)                — function codes 1, 5, 15
    0  PUMP_RUN        1 = inlet pump running
    1  VALVE_OPEN      1 = outlet valve open
    2  ALARM_ACK       operator alarm-acknowledge button (write 1 to clear)

Discrete Inputs (read-only bits)       — function code 2
    0  LEVEL_HIGH_SW   high-level float switch tripped
    1  LEVEL_LOW_SW    low-level float switch tripped
    2  E_STOP          emergency stop (simulated, normally 0)

Holding Registers (read/write words)   — function codes 3, 6, 16
    0  LEVEL_SETPOINT  desired tank level, 0-1000 (0.0-100.0%)
    1  PUMP_SPEED_SP   commanded pump speed, 0-100 (%)
    2  SCAN_TIME_MS    simulated PLC scan time in ms (cosmetic)

Input Registers (read-only words)      — function code 4
    0  TANK_LEVEL      current tank level, 0-1000 (0.0-100.0%)
    1  FLOW_RATE       current inlet flow rate (arbitrary scaled units)
    2  ALARM_WORD      bitmask: bit0=high level, bit1=low level, bit2=e-stop
    3  UPTIME_S        seconds since emulator start (low 16 bits)
--------------------------------------------------------------------------

Usage:
    python3 plc_emulator.py --host 0.0.0.0 --port 5020 --unit-id 1 --name PLC-1
    (use --port 502 to look like a real PLC on the wire; needs root/cap_net_bind)

Run multiple instances (different --port, and/or bind different host IPs
aliased on the interface, and/or different --unit-id) to populate a segment
with several simulated PLCs for traffic-generation / detection exercises.
"""

import argparse
import asyncio
import logging
import time
from dataclasses import dataclass

from pymodbus.datastore import (
    ModbusSlaveContext,
    ModbusServerContext,
    ModbusSequentialDataBlock,
)
from pymodbus.device import ModbusDeviceIdentification
from pymodbus.server import StartAsyncTcpServer

log = logging.getLogger("plc_emulator")

# --------------------------------------------------------------------------
# Register address map (kept as constants so the physics loop, the datastore
# setup, and the docstring above all agree with each other).
# --------------------------------------------------------------------------
CO_PUMP_RUN, CO_VALVE_OPEN, CO_ALARM_ACK = 0, 1, 2
DI_LEVEL_HIGH, DI_LEVEL_LOW, DI_ESTOP = 0, 1, 2
HR_LEVEL_SP, HR_PUMP_SPEED_SP, HR_SCAN_TIME = 0, 1, 2
IR_TANK_LEVEL, IR_FLOW_RATE, IR_ALARM_WORD, IR_UPTIME = 0, 1, 2, 3


class LoggingSlaveContext(ModbusSlaveContext):
    """Thin wrapper that logs every Modbus request that touches this device.

    In a real exercise you'd point this at a file / your SIEM ingestion
    instead of stdout, but stdout is fine for getting started.
    """

    def __init__(self, name, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._name = name

    def setValues(self, fx, address, values):
        log.info("[%s] WRITE fx=%s addr=%s values=%s", self._name, fx, address, values)
        super().setValues(fx, address, values)

    def getValues(self, fx, address, count=1):
        values = super().getValues(fx, address, count)
        log.debug("[%s] READ  fx=%s addr=%s count=%s -> %s", self._name, fx, address, count, values)
        return values


@dataclass
class ProcessState:
    level_x10: float = 300.0  # tank level, fixed point *10 (0-1000 == 0.0-100.0%)


async def run_physics(slave: ModbusSlaveContext, name: str, tick_hz: float = 5.0):
    """
    Background task simulating a simple tank-level process:
      - pump adds level proportional to PUMP_SPEED_SP when PUMP_RUN coil is set
      - VALVE_OPEN coil drains the tank
      - float switches trip at 90% / 10% and set the alarm word / discrete inputs

    This is intentionally simple. Swap in your own process model (multi-tank,
    PID loop, conveyor, batch sequencer, whatever your exercise needs) by
    editing this function only — the Modbus plumbing doesn't need to change.
    Internal process updates write directly via ModbusSlaveContext.setValues
    (bypassing the logging wrapper) so the traffic log only shows writes that
    actually came in over the wire, not the simulator's own bookkeeping.
    """
    state = ProcessState()
    start = time.monotonic()
    period = 1.0 / tick_hz

    while True:
        await asyncio.sleep(period)

        pump_run = slave.getValues(1, CO_PUMP_RUN, 1)[0]
        valve_open = slave.getValues(1, CO_VALVE_OPEN, 1)[0]
        pump_speed = slave.getValues(3, HR_PUMP_SPEED_SP, 1)[0]

        flow_in = (pump_speed / 100.0) * 8.0 if pump_run else 0.0
        flow_out = 6.0 if valve_open else 0.0

        state.level_x10 += (flow_in - flow_out)
        state.level_x10 = max(0.0, min(1000.0, state.level_x10))

        level_high = 1 if state.level_x10 >= 900 else 0
        level_low = 1 if state.level_x10 <= 100 else 0
        alarm_word = (level_high << 0) | (level_low << 1)

        uptime = int(time.monotonic() - start) & 0xFFFF

        ModbusSlaveContext.setValues(slave, 4, IR_TANK_LEVEL, [int(state.level_x10)])
        ModbusSlaveContext.setValues(slave, 4, IR_FLOW_RATE, [int(flow_in * 10)])
        ModbusSlaveContext.setValues(slave, 4, IR_ALARM_WORD, [alarm_word])
        ModbusSlaveContext.setValues(slave, 4, IR_UPTIME, [uptime])
        ModbusSlaveContext.setValues(slave, 2, DI_LEVEL_HIGH, [level_high])
        ModbusSlaveContext.setValues(slave, 2, DI_LEVEL_LOW, [level_low])

        log.debug(
            "[%s] process tick: level=%.1f%% pump=%s valve=%s flow_in=%.1f",
            name, state.level_x10 / 10.0, pump_run, valve_open, flow_in,
        )


def build_context(name: str):
    co = ModbusSequentialDataBlock(0, [0] * 16)
    di = ModbusSequentialDataBlock(0, [0] * 16)
    hr = ModbusSequentialDataBlock(0, [0] * 16)
    ir = ModbusSequentialDataBlock(0, [0] * 16)

    slave = LoggingSlaveContext(name, di=di, co=co, ir=ir, hr=hr)

    # Starting setpoints so the process is doing something interesting the
    # moment the emulator comes up.
    slave.setValues(3, HR_LEVEL_SP, [500])
    slave.setValues(3, HR_PUMP_SPEED_SP, [50])
    slave.setValues(3, HR_SCAN_TIME, [100])
    slave.setValues(1, CO_PUMP_RUN, [1])

    context = ModbusServerContext(slaves=slave, single=True)
    return context, slave


async def main_async(args: argparse.Namespace):
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)-7s %(message)s",
    )

    context, slave = build_context(args.name)

    identity = ModbusDeviceIdentification()
    identity.VendorName = args.vendor
    identity.ProductCode = args.product_code
    identity.VendorUrl = "http://example.invalid"
    identity.ProductName = args.name
    identity.ModelName = args.model
    identity.MajorMinorRevision = "1.0"

    physics_task = asyncio.create_task(run_physics(slave, args.name))

    log.info(
        "Starting emulated PLC '%s' (vendor=%s model=%s) on %s:%d, unit id %d",
        args.name, args.vendor, args.model, args.host, args.port, args.unit_id,
    )
    try:
        await StartAsyncTcpServer(context=context, identity=identity, address=(args.host, args.port))
    finally:
        physics_task.cancel()


def parse_args():
    p = argparse.ArgumentParser(description="Emulate a Modbus/TCP PLC for ICS security lab traffic generation.")
    p.add_argument("--host", default="0.0.0.0", help="Address to bind (default: 0.0.0.0)")
    p.add_argument("--port", type=int, default=5020, help="TCP port (default: 5020; use 502 if running as root)")
    p.add_argument("--unit-id", type=int, default=1, help="Modbus unit/slave id (default: 1)")
    p.add_argument("--name", default="PLC-1", help="Friendly name for logging (default: PLC-1)")
    p.add_argument("--vendor", default="Generic Controls Inc.", help="Simulated vendor name in device identification")
    p.add_argument("--model", default="GC-3000", help="Simulated model name in device identification")
    p.add_argument("--product-code", default="GC3000", help="Simulated product code")
    p.add_argument("-v", "--verbose", action="store_true", help="Verbose (per-tick / per-read) logging")
    return p.parse_args()


if __name__ == "__main__":
    args = parse_args()
    try:
        asyncio.run(main_async(args))
    except KeyboardInterrupt:
        pass
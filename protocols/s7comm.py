from __future__ import annotations

import asyncio
import contextlib
import logging

from snap7.server import Server as S7Server
from snap7.type import SrvArea

from emulator_core import EmulatorConfig, ProcessImage
from protocols import register_protocol
from protocols.base import ProtocolBackend


log = logging.getLogger("plc_emulator")

S7_DB_PROCESS = 1
S7_DB_CONTROL = 2
S7_DB_ENGINEERING = 900
S7_DB_PROCESS_SIZE = 32
S7_DB_CONTROL_SIZE = 32
S7_DB_ENGINEERING_SIZE = 4096


def build_engineering_blob(config: EmulatorConfig) -> bytearray:
    blob = bytearray(S7_DB_ENGINEERING_SIZE)
    banner = (
        f"PLC={config.name}\n"
        f"VENDOR={config.vendor}\n"
        f"MODEL={config.model}\n"
        f"PRODUCT={config.product_code}\n"
        f"PROTOCOL=S7COMM\n"
    ).encode("ascii", errors="ignore")
    repeated = (banner + b"-" * 32) * 64
    blob[: min(len(blob), len(repeated))] = repeated[: len(blob)]
    return blob


@register_protocol("s7comm")
class S7CommBackend(ProtocolBackend):
    async def serve(self, config: EmulatorConfig, image: ProcessImage) -> None:
        process_db = bytearray(S7_DB_PROCESS_SIZE)
        control_db = bytearray(S7_DB_CONTROL_SIZE)
        engineering_db = build_engineering_blob(config)
        image.sync_to_s7(process_db, control_db, engineering_db)

        server = S7Server(log=False)
        server.register_area(SrvArea.DB, S7_DB_PROCESS, process_db)
        server.register_area(SrvArea.DB, S7_DB_CONTROL, control_db)
        server.register_area(SrvArea.DB, S7_DB_ENGINEERING, engineering_db)

        def log_event(event) -> None:
            try:
                log.info("[%s] S7 %s", config.name, server.event_text(event))
            except Exception:
                log.info("[%s] S7 event: %r", config.name, event)

        server.set_events_callback(log_event)
        server.set_read_events_callback(log_event)
        server.start_to(config.host, tcp_port=config.port)

        log.info(
            "Starting %s backend for '%s' (vendor=%s model=%s) on %s:%d",
            config.protocol,
            config.name,
            config.vendor,
            config.model,
            config.host,
            config.port,
        )
        try:
            while True:
                image.sync_from_s7_controls(control_db)
                image.sync_to_s7(process_db, control_db, engineering_db)
                await asyncio.sleep(0.2)
        finally:
            with contextlib.suppress(Exception):
                server.stop()
            with contextlib.suppress(Exception):
                server.destroy()

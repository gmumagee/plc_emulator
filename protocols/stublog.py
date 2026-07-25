from __future__ import annotations

import asyncio
import logging

from emulator_core import EmulatorConfig, ProcessImage
from protocols import register_protocol
from protocols.base import ProtocolBackend


log = logging.getLogger("plc_emulator")


@register_protocol("stublog")
class StubLogBackend(ProtocolBackend):
    """Minimal backend used to prove auto-discovery of new protocol modules."""

    async def serve(self, config: EmulatorConfig, image: ProcessImage) -> None:
        async def handle_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
            peer = writer.get_extra_info("peername")
            log.info("[%s] stublog accepted connection from %s", config.name, peer)
            writer.write(b"stublog\n")
            await writer.drain()
            writer.close()
            await writer.wait_closed()

        server = await asyncio.start_server(handle_client, config.host, config.port)
        sockets = ", ".join(str(sock.getsockname()) for sock in (server.sockets or []))
        log.info("Starting %s backend for '%s' on %s", config.protocol, config.name, sockets)
        async with server:
            await server.serve_forever()

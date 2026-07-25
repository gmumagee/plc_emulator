#!/usr/bin/env python3
"""Protocol-aware PLC emulator with plugin backends."""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import logging

from emulator_core import ProcessImage, resolve_config_from_args, run_physics
from protocols import discover_protocol_backends


log = logging.getLogger("plc_emulator")


def parse_args(available_protocols: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Emulate a PLC for ICS security lab traffic generation.")
    parser.add_argument("--plc-type", help="PLC type key from plc_types.json")
    parser.add_argument("--host", default="0.0.0.0", help="Address to bind (default: 0.0.0.0)")
    parser.add_argument("--port", type=int, default=None, help="TCP port to bind; defaults from plc_types.json")
    parser.add_argument("--protocol", choices=available_protocols, help="Protocol backend to run")
    parser.add_argument("--unit-id", type=int, default=1, help="Modbus unit/slave id (default: 1)")
    parser.add_argument("--name", default="PLC-1", help="Friendly name for logging (default: PLC-1)")
    parser.add_argument("--vendor", default=None, help="Override vendor string")
    parser.add_argument("--model", default=None, help="Override model string")
    parser.add_argument("--product-code", default=None, help="Override product code")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose logging")
    return parser.parse_args()


async def main_async(args: argparse.Namespace) -> None:
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)-7s %(message)s",
    )

    config = resolve_config_from_args(args)
    backends = discover_protocol_backends()
    backend_class = backends.get(config.protocol)
    if backend_class is None:
        raise SystemExit(
            f"protocol '{config.protocol}' is not available. "
            f"Discovered backends: {', '.join(sorted(backends))}"
        )

    image = ProcessImage()
    physics_task = asyncio.create_task(run_physics(image))
    backend = backend_class()

    try:
        await backend.serve(config, image)
    finally:
        physics_task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await physics_task


if __name__ == "__main__":
    protocols = sorted(discover_protocol_backends())
    cli_args = parse_args(protocols)
    try:
        asyncio.run(main_async(cli_args))
    except KeyboardInterrupt:
        pass

"""Base contract for protocol backends.

To add a new protocol backend:

1. Create `protocols/<name>.py`
2. Import `ProtocolBackend` and `register_protocol`
3. Define a class that implements `async def serve(config, image)`
4. Decorate it with `@register_protocol("<name>")`

No dispatcher edits are required in `plc_emulator.py`.
"""

from __future__ import annotations

from emulator_core import EmulatorConfig, ProcessImage


class ProtocolBackend:
    """Duck-typed backend contract for protocol plugins."""

    protocol_name = ""

    async def serve(self, config: EmulatorConfig, image: ProcessImage) -> None:
        raise NotImplementedError

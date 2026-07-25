from __future__ import annotations

import logging

from pymodbus.datastore import ModbusSequentialDataBlock, ModbusServerContext, ModbusSlaveContext
from pymodbus.device import ModbusDeviceIdentification
from pymodbus.server import StartAsyncTcpServer

from emulator_core import EmulatorConfig, ProcessImage
from protocols import register_protocol
from protocols.base import ProtocolBackend


log = logging.getLogger("plc_emulator")


class ImageSlaveContext(ModbusSlaveContext):
    def __init__(self, name: str, image: ProcessImage, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._name = name
        self._image = image

    def setValues(self, fx, address, values):
        log.info("[%s] WRITE fx=%s addr=%s values=%s", self._name, fx, address, values)
        self._image.apply_modbus_write(int(fx), int(address), list(values))
        super().setValues(fx, address, values)

    def getValues(self, fx, address, count=1):
        values = self._image.read_modbus(int(fx), int(address), int(count))
        log.debug("[%s] READ  fx=%s addr=%s count=%s -> %s", self._name, fx, address, count, values)
        return values


def build_context(name: str, image: ProcessImage) -> ModbusServerContext:
    co = ModbusSequentialDataBlock(0, [0] * 16)
    di = ModbusSequentialDataBlock(0, [0] * 16)
    hr = ModbusSequentialDataBlock(0, [0] * 16)
    ir = ModbusSequentialDataBlock(0, [0] * 16)
    slave = ImageSlaveContext(name, image, di=di, co=co, ir=ir, hr=hr)
    return ModbusServerContext(slaves=slave, single=True)


@register_protocol("modbus")
class ModbusBackend(ProtocolBackend):
    async def serve(self, config: EmulatorConfig, image: ProcessImage) -> None:
        context = build_context(config.name, image)
        identity = ModbusDeviceIdentification()
        identity.VendorName = config.vendor
        identity.ProductCode = config.product_code
        identity.VendorUrl = "http://example.invalid"
        identity.ProductName = config.name
        identity.ModelName = config.model
        identity.MajorMinorRevision = "1.0"

        log.info(
            "Starting %s backend for '%s' (vendor=%s model=%s) on %s:%d, unit id %d",
            config.protocol,
            config.name,
            config.vendor,
            config.model,
            config.host,
            config.port,
            config.unit_id,
        )
        await StartAsyncTcpServer(
            context=context,
            identity=identity,
            address=(config.host, config.port),
        )

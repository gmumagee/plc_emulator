from __future__ import annotations

import asyncio
import contextlib
import logging
import struct
import time
from dataclasses import dataclass
from typing import Any

from emulator_core import EmulatorConfig, ProcessImage
from protocols import register_protocol
from protocols.base import ProtocolBackend


log = logging.getLogger("plc_emulator")

FINS_HEADER_SIZE = 10
FINS_CMD_MEMORY_READ = 0x0101
FINS_CMD_MEMORY_WRITE = 0x0102
FINS_END_OK = 0x0000
FINS_ERR_UNSUPPORTED_COMMAND = 0x0401
FINS_ERR_PARAMETER = 0x1101
FINS_ERR_READ_ONLY = 0x2108
FINS_ERR_AREA_CODE = 0x1103

FINS_AREA_COIL_BIT = 0x30
FINS_AREA_DI_BIT = 0x31
FINS_AREA_INPUT_WORD = 0xB1
FINS_AREA_HOLDING_WORD = 0x82


@dataclass(frozen=True)
class FinsAreaSpec:
    area_code: int
    point_kind: str
    bytes_per_item: int
    bit_access: bool


@dataclass
class FinsRequest:
    icf: int
    rsv: int
    gct: int
    dna: int
    da1: int
    da2: int
    sna: int
    sa1: int
    sa2: int
    sid: int
    command: int
    payload: bytes


@dataclass
class FinsPeer:
    addr: tuple[str, int]
    network: int
    node: int
    unit: int
    last_seen: float


AREA_SPECS = {
    FINS_AREA_COIL_BIT: FinsAreaSpec(FINS_AREA_COIL_BIT, "coil", 1, True),
    FINS_AREA_DI_BIT: FinsAreaSpec(FINS_AREA_DI_BIT, "discrete_input", 1, True),
    FINS_AREA_INPUT_WORD: FinsAreaSpec(FINS_AREA_INPUT_WORD, "input_register", 2, False),
    FINS_AREA_HOLDING_WORD: FinsAreaSpec(FINS_AREA_HOLDING_WORD, "holding_register", 2, False),
}

POINT_KIND_TO_AREA = {
    "coil": FINS_AREA_COIL_BIT,
    "discrete_input": FINS_AREA_DI_BIT,
    "input_register": FINS_AREA_INPUT_WORD,
    "holding_register": FINS_AREA_HOLDING_WORD,
}


def _node_from_host(host: str) -> int:
    try:
        candidate = int(host.rsplit(".", 1)[-1])
    except (TypeError, ValueError):
        return 1
    return max(1, min(254, candidate))


def _parse_request(data: bytes) -> FinsRequest | None:
    if len(data) < FINS_HEADER_SIZE + 2:
        return None
    header = data[:FINS_HEADER_SIZE]
    command = struct.unpack(">H", data[FINS_HEADER_SIZE : FINS_HEADER_SIZE + 2])[0]
    return FinsRequest(
        icf=header[0],
        rsv=header[1],
        gct=header[2],
        dna=header[3],
        da1=header[4],
        da2=header[5],
        sna=header[6],
        sa1=header[7],
        sa2=header[8],
        sid=header[9],
        command=command,
        payload=data[FINS_HEADER_SIZE + 2 :],
    )


def _build_response_header(req: FinsRequest) -> bytes:
    return bytes([0xC0, req.rsv, req.gct, req.sna, req.sa1, req.sa2, req.dna, req.da1, req.da2, req.sid])


def _build_request_header(*, destination: FinsPeer, source_node: int, source_unit: int, sid: int, response_required: bool) -> bytes:
    icf = 0x80 if response_required else 0x81
    return bytes([icf, 0x00, 0x02, destination.network, destination.node, destination.unit, 0x00, source_node, source_unit, sid])


def _encode_address(word_address: int, bit_offset: int) -> bytes:
    return struct.pack(">H", word_address) + bytes([bit_offset & 0x0F])


def _decode_address(payload: bytes) -> tuple[int, int, int, int] | None:
    if len(payload) < 6:
        return None
    area_code = payload[0]
    word_address = struct.unpack(">H", payload[1:3])[0]
    bit_offset = payload[3]
    count = struct.unpack(">H", payload[4:6])[0]
    return area_code, word_address, bit_offset, count


def _group_contiguous(points: list[Any]) -> list[list[Any]]:
    if not points:
        return []
    ordered = sorted(points, key=lambda point: point.address)
    groups: list[list[Any]] = [[ordered[0]]]
    for point in ordered[1:]:
        current = groups[-1]
        if point.address == current[-1].address + 1:
            current.append(point)
        else:
            groups.append([point])
    return groups


class FinsMemoryModel:
    def __init__(self, image: ProcessImage):
        self.image = image

    def read_items(self, area_code: int, word_address: int, bit_offset: int, count: int) -> tuple[int, bytes]:
        spec = AREA_SPECS.get(area_code)
        if spec is None:
            return FINS_ERR_AREA_CODE, b""
        if count <= 0:
            return FINS_ERR_PARAMETER, b""

        if spec.bit_access:
            return FINS_END_OK, self._read_bits(spec.point_kind, word_address, bit_offset, count)
        if bit_offset != 0:
            return FINS_ERR_PARAMETER, b""
        return FINS_END_OK, self._read_words(spec.point_kind, word_address, count)

    def write_items(self, area_code: int, word_address: int, bit_offset: int, count: int, data: bytes) -> int:
        spec = AREA_SPECS.get(area_code)
        if spec is None:
            return FINS_ERR_AREA_CODE
        if count <= 0:
            return FINS_ERR_PARAMETER
        if spec.point_kind not in {"coil", "holding_register"}:
            return FINS_ERR_READ_ONLY

        if spec.bit_access:
            if len(data) < count:
                return FINS_ERR_PARAMETER
            self._write_bits(spec.point_kind, word_address, bit_offset, list(data[:count]))
            return FINS_END_OK

        if bit_offset != 0 or len(data) < count * 2:
            return FINS_ERR_PARAMETER
        values = [struct.unpack(">H", data[offset : offset + 2])[0] for offset in range(0, count * 2, 2)]
        self._write_words(spec.point_kind, word_address, values)
        return FINS_END_OK

    def raw_state(self, point_kinds: tuple[str, ...]) -> dict[str, int]:
        snapshot: dict[str, int] = {}
        with self.image.lock:
            for point in self.image.device.points:
                if point.kind in point_kinds:
                    snapshot[point.id] = self.image.read_raw_point(point)
        return snapshot

    def unsolicited_packets(self, *, peer: FinsPeer, source_node: int, source_unit: int, sid: int) -> list[bytes]:
        packets: list[bytes] = []
        with self.image.lock:
            for kind in ("discrete_input", "input_register"):
                points = [point for point in self.image.device.points if point.kind == kind]
                if not points:
                    continue
                spec = AREA_SPECS[POINT_KIND_TO_AREA[kind]]
                for group in _group_contiguous(points):
                    if spec.bit_access:
                        start = group[0].address
                        word = start // 16
                        bit = start % 16
                        payload_data = bytes(self._bit_values_unlocked(kind, start, len(group)))
                    else:
                        word = group[0].address
                        bit = 0
                        payload_data = b"".join(
                            struct.pack(">H", self.image.read_raw_point(point))
                            for point in group
                        )
                    header = _build_request_header(
                        destination=peer,
                        source_node=source_node,
                        source_unit=source_unit,
                        sid=sid,
                        response_required=False,
                    )
                    packet = (
                        header
                        + struct.pack(">H", FINS_CMD_MEMORY_WRITE)
                        + bytes([spec.area_code])
                        + _encode_address(word, bit)
                        + struct.pack(">H", len(group))
                        + payload_data
                    )
                    packets.append(packet)
                    sid = (sid + 1) & 0xFF
        return packets

    def _read_bits(self, point_kind: str, word_address: int, bit_offset: int, count: int) -> bytes:
        start = (word_address * 16) + bit_offset
        with self.image.lock:
            values = self._bit_values_unlocked(point_kind, start, count)
        return bytes(values)

    def _bit_values_unlocked(self, point_kind: str, start: int, count: int) -> list[int]:
        values: list[int] = []
        for offset in range(count):
            point = self.image.points_by_kind_address.get((point_kind, start + offset))
            values.append(self.image.read_raw_point(point) if point else 0)
        return values

    def _read_words(self, point_kind: str, word_address: int, count: int) -> bytes:
        payload = bytearray()
        with self.image.lock:
            for offset in range(count):
                point = self.image.points_by_kind_address.get((point_kind, word_address + offset))
                payload.extend(struct.pack(">H", self.image.read_raw_point(point) if point else 0))
        return bytes(payload)

    def _write_bits(self, point_kind: str, word_address: int, bit_offset: int, values: list[int]) -> None:
        start = (word_address * 16) + bit_offset
        with self.image.lock:
            for offset, raw_value in enumerate(values):
                point = self.image.points_by_kind_address.get((point_kind, start + offset))
                if point is None or not point.writable:
                    continue
                self.image.write_raw_point(point, 1 if raw_value else 0)

    def _write_words(self, point_kind: str, word_address: int, values: list[int]) -> None:
        with self.image.lock:
            for offset, raw_value in enumerate(values):
                point = self.image.points_by_kind_address.get((point_kind, word_address + offset))
                if point is None or not point.writable:
                    continue
                self.image.write_raw_point(point, raw_value)


class FinsUdpProtocol(asyncio.DatagramProtocol):
    def __init__(self, config: EmulatorConfig, image: ProcessImage):
        self.config = config
        self.image = image
        self.model = FinsMemoryModel(image)
        self.transport: asyncio.DatagramTransport | None = None
        self.last_peer: FinsPeer | None = None
        self.local_node = _node_from_host(config.host)
        self.local_unit = 0
        self.next_sid = 1
        params = config.device.simulation.params if config.device is not None else {}
        self.unsolicited_interval = max(1.0, float(params.get("fins_unsolicited_interval", 1.0)))
        self.unsolicited_state = self.model.raw_state(("discrete_input", "input_register"))
        self.next_unsolicited_due = time.monotonic() + self.unsolicited_interval
        self.pending_unsolicited = False

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        self.transport = transport  # type: ignore[assignment]
        sockname = self.transport.get_extra_info("sockname")
        log.info(
            "Starting %s backend for '%s' (vendor=%s model=%s) on %s",
            self.config.protocol,
            self.config.name,
            self.config.vendor,
            self.config.model,
            sockname,
        )

    def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
        req = _parse_request(data)
        if req is None:
            log.warning("[%s] FINS short datagram from %s (%d bytes)", self.config.name, addr, len(data))
            return
        first_peer = self.last_peer is None
        self.last_peer = FinsPeer(addr=addr, network=req.sna, node=req.sa1, unit=req.sa2, last_seen=time.time())
        if first_peer:
            self.next_unsolicited_due = min(self.next_unsolicited_due, time.monotonic() + 0.2)

        response_required = (req.icf & 0x01) == 0
        response = self._handle_request(req, addr)
        if response_required and response is not None and self.transport is not None:
            self.transport.sendto(response, addr)

    def error_received(self, exc: Exception) -> None:
        log.warning("[%s] FINS UDP error: %s", self.config.name, exc)

    def connection_lost(self, exc: Exception | None) -> None:
        if exc:
            log.warning("[%s] FINS UDP transport lost: %s", self.config.name, exc)

    async def unsolicited_loop(self) -> None:
        while True:
            await asyncio.sleep(0.5)
            if self.transport is None or self.last_peer is None:
                continue
            now = time.monotonic()
            current = self.model.raw_state(("discrete_input", "input_register"))
            changed = current != self.unsolicited_state
            if changed:
                self.pending_unsolicited = True
            if now < self.next_unsolicited_due:
                continue
            if not self.pending_unsolicited:
                self.next_unsolicited_due = now + self.unsolicited_interval
                continue

            sid = self._next_sid()
            packets = self.model.unsolicited_packets(
                peer=self.last_peer,
                source_node=self.local_node,
                source_unit=self.local_unit,
                sid=sid,
            )
            for packet in packets:
                self.transport.sendto(packet, self.last_peer.addr)
            self.unsolicited_state = current
            self.pending_unsolicited = False
            self.next_unsolicited_due = now + self.unsolicited_interval
            if packets:
                log.info(
                    "[%s] FINS unsolicited update sent to %s (%d packet%s)%s",
                    self.config.name,
                    self.last_peer.addr,
                    len(packets),
                    "" if len(packets) == 1 else "s",
                    " after state change" if changed else "",
                )

    def _handle_request(self, req: FinsRequest, addr: tuple[str, int]) -> bytes | None:
        if req.command == FINS_CMD_MEMORY_READ:
            return self._handle_memory_read(req, addr)
        if req.command == FINS_CMD_MEMORY_WRITE:
            return self._handle_memory_write(req, addr)

        log.info("[%s] FINS unsupported command 0x%04X from %s", self.config.name, req.command, addr)
        return _build_response_header(req) + struct.pack(">H", req.command) + struct.pack(">H", FINS_ERR_UNSUPPORTED_COMMAND)

    def _handle_memory_read(self, req: FinsRequest, addr: tuple[str, int]) -> bytes:
        decoded = _decode_address(req.payload)
        if decoded is None:
            return _build_response_header(req) + struct.pack(">H", req.command) + struct.pack(">H", FINS_ERR_PARAMETER)
        area_code, word_address, bit_offset, count = decoded
        end_code, data = self.model.read_items(area_code, word_address, bit_offset, count)
        log.info(
            "[%s] FINS READ area=0x%02X word=%d bit=%d count=%d from=%s end=0x%04X",
            self.config.name,
            area_code,
            word_address,
            bit_offset,
            count,
            addr,
            end_code,
        )
        return _build_response_header(req) + struct.pack(">H", req.command) + struct.pack(">H", end_code) + data

    def _handle_memory_write(self, req: FinsRequest, addr: tuple[str, int]) -> bytes:
        decoded = _decode_address(req.payload)
        if decoded is None:
            return _build_response_header(req) + struct.pack(">H", req.command) + struct.pack(">H", FINS_ERR_PARAMETER)
        area_code, word_address, bit_offset, count = decoded
        data = req.payload[6:]
        end_code = self.model.write_items(area_code, word_address, bit_offset, count, data)
        log.info(
            "[%s] FINS WRITE area=0x%02X word=%d bit=%d count=%d from=%s end=0x%04X",
            self.config.name,
            area_code,
            word_address,
            bit_offset,
            count,
            addr,
            end_code,
        )
        return _build_response_header(req) + struct.pack(">H", req.command) + struct.pack(">H", end_code)

    def _next_sid(self) -> int:
        sid = self.next_sid
        self.next_sid = (self.next_sid + 1) & 0xFF
        return sid


@register_protocol("fins")
class FinsBackend(ProtocolBackend):
    async def serve(self, config: EmulatorConfig, image: ProcessImage) -> None:
        loop = asyncio.get_running_loop()
        protocol = FinsUdpProtocol(config, image)
        transport, _ = await loop.create_datagram_endpoint(
            lambda: protocol,
            local_addr=(config.host, config.port),
        )
        unsolicited_task = asyncio.create_task(protocol.unsolicited_loop())
        try:
            await asyncio.Future()
        finally:
            unsolicited_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await unsolicited_task
            transport.close()

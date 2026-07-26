from __future__ import annotations

import asyncio
import contextlib
import logging
import socket
import struct
import zlib
from dataclasses import dataclass, field

from emulator_core import EmulatorConfig, ProcessImage
from protocols import register_protocol
from protocols.base import ProtocolBackend


log = logging.getLogger("plc_emulator")

ENIP_HEADER = struct.Struct("<HHII8sI")
ENIP_CMD_LIST_SERVICES = 0x0004
ENIP_CMD_LIST_IDENTITY = 0x0063
ENIP_CMD_REGISTER_SESSION = 0x0065
ENIP_CMD_UNREGISTER_SESSION = 0x0066
ENIP_CMD_SEND_RR_DATA = 0x006F

CPF_NULL_ADDRESS = 0x0000
CPF_LIST_IDENTITY = 0x000C
CPF_UNCONNECTED_DATA = 0x00B2
CPF_CONNECTED_ADDRESS = 0x00A1
CPF_CONNECTED_DATA = 0x00B1
CPF_SEQUENCED_ADDRESS = 0x8002

CIP_SERVICE_GET_ATTRIBUTE_ALL = 0x01
CIP_SERVICE_GET_ATTRIBUTE_SINGLE = 0x0E
CIP_SERVICE_SET_ATTRIBUTE_SINGLE = 0x10
CIP_SERVICE_FORWARD_CLOSE = 0x4E
CIP_SERVICE_FORWARD_OPEN = 0x54

CIP_CLASS_IDENTITY = 0x01
CIP_CLASS_ASSEMBLY = 0x04
CIP_CLASS_CONNECTION_MANAGER = 0x06
CIP_CLASS_LAB_POINT = 0x70

CIP_STATUS_SUCCESS = 0x00
CIP_STATUS_INVALID_PARAMETER = 0x03
CIP_STATUS_PATH_DESTINATION_UNKNOWN = 0x05
CIP_STATUS_SERVICE_NOT_SUPPORTED = 0x08
CIP_STATUS_ATTRIBUTE_NOT_SUPPORTED = 0x14
CIP_STATUS_OBJECT_STATE_CONFLICT = 0x10
CIP_STATUS_INSUFFICIENT_ACCESS = 0x0F

DEVICE_TYPE_PROGRAMMABLE_CONTROLLER = 0x000E
ASSEMBLY_OUTPUT_INSTANCE = 100
ASSEMBLY_INPUT_INSTANCE = 101
IMPLICIT_UDP_PORT = 2222


def _u16(value: int) -> bytes:
    return struct.pack("<H", value & 0xFFFF)


def _u32(value: int) -> bytes:
    return struct.pack("<I", value & 0xFFFFFFFF)


def _short_string(value: str) -> bytes:
    payload = value.encode("ascii", errors="ignore")[:255]
    return bytes([len(payload)]) + payload


def _pack_cpf(items: list[tuple[int, bytes]]) -> bytes:
    payload = bytearray(struct.pack("<H", len(items)))
    for item_type, item_data in items:
        payload.extend(struct.pack("<HH", item_type, len(item_data)))
        payload.extend(item_data)
    return bytes(payload)


def _pack_rr_data(cip_payload: bytes) -> bytes:
    return struct.pack("<IH", 0, 0) + _pack_cpf(
        [
            (CPF_NULL_ADDRESS, b""),
            (CPF_UNCONNECTED_DATA, cip_payload),
        ]
    )


def _response_message(service: int, status: int, data: bytes = b"", additional_status: tuple[int, ...] = ()) -> bytes:
    payload = bytearray([service | 0x80, 0x00, status, len(additional_status)])
    for word in additional_status:
        payload.extend(_u16(word))
    payload.extend(data)
    return bytes(payload)


def _parse_epath(path_bytes: bytes) -> tuple[int | None, int | None, int | None, list[int]]:
    class_id: int | None = None
    instance_id: int | None = None
    attribute_id: int | None = None
    segments: list[int] = []
    idx = 0
    while idx < len(path_bytes):
        segment = path_bytes[idx]
        if segment == 0x00:
            idx += 1
            continue
        if idx + 1 >= len(path_bytes):
            break
        value8 = path_bytes[idx + 1]
        if segment == 0x20:
            class_id = value8
            segments.append(value8)
            idx += 2
        elif segment == 0x24:
            instance_id = value8
            segments.append(value8)
            idx += 2
        elif segment == 0x30:
            attribute_id = value8
            segments.append(value8)
            idx += 2
        elif segment == 0x21 and idx + 3 < len(path_bytes):
            class_id = struct.unpack_from("<H", path_bytes, idx + 2)[0]
            segments.append(class_id)
            idx += 4
        elif segment == 0x25 and idx + 3 < len(path_bytes):
            instance_id = struct.unpack_from("<H", path_bytes, idx + 2)[0]
            segments.append(instance_id)
            idx += 4
        elif segment == 0x31 and idx + 3 < len(path_bytes):
            attribute_id = struct.unpack_from("<H", path_bytes, idx + 2)[0]
            segments.append(attribute_id)
            idx += 4
        else:
            break
    return class_id, instance_id, attribute_id, segments


def _parse_message_router_request(payload: bytes) -> tuple[int, bytes, bytes] | None:
    if len(payload) < 2:
        return None
    service = payload[0]
    path_words = payload[1]
    path_length = path_words * 2
    if len(payload) < 2 + path_length:
        return None
    path = payload[2 : 2 + path_length]
    data = payload[2 + path_length :]
    return service, path, data


def _vendor_id_from_name(vendor: str) -> int:
    known = {
        "Allen-Bradley": 1,
        "Rockwell Automation": 1,
        "Schneider Electric": 493,
        "Siemens": 25,
        "Omron": 58,
        "Mitsubishi Electric": 246,
    }
    return known.get(vendor, 0x1337)


def _numeric_product_code(product_code: str) -> int:
    digits = "".join(ch for ch in product_code if ch.isdigit())
    if digits:
        try:
            return int(digits[-5:]) & 0xFFFF
        except ValueError:
            pass
    return zlib.crc32(product_code.encode("ascii", errors="ignore")) & 0xFFFF


def _serial_number(config: EmulatorConfig) -> int:
    seed = f"{config.vendor}|{config.model}|{config.product_code}|{config.device_type or ''}"
    return zlib.crc32(seed.encode("ascii", errors="ignore")) & 0xFFFFFFFF


@dataclass
class EnipSession:
    handle: int
    peer: tuple[str, int]


@dataclass
class ForwardOpenConnection:
    session_handle: int
    peer_host: str
    peer_port: int
    output_connection_id: int
    input_connection_id: int
    connection_serial: int
    originator_vendor_id: int
    originator_serial_number: int
    requested_packet_interval_us: int
    opened_monotonic: float
    transport_type_trigger: int = 0
    sequence: int = 0
    next_due: float = field(default=0.0)

    @property
    def rpi_seconds(self) -> float:
        return max(0.010, self.requested_packet_interval_us / 1_000_000.0)


class CipImageModel:
    def __init__(self, config: EmulatorConfig, image: ProcessImage):
        self.config = config
        self.image = image
        self.point_instances = list(image.device.points)
        self.point_instance_map = {index + 1: point for index, point in enumerate(self.point_instances)}

    def identity_attribute(self, attribute_id: int) -> bytes | None:
        if attribute_id == 1:
            return _u16(_vendor_id_from_name(self.config.vendor))
        if attribute_id == 2:
            return _u16(DEVICE_TYPE_PROGRAMMABLE_CONTROLLER)
        if attribute_id == 3:
            return _u16(_numeric_product_code(self.config.product_code))
        if attribute_id == 4:
            return bytes([1, 0])
        if attribute_id == 5:
            return _u16(0)
        if attribute_id == 6:
            return _u32(_serial_number(self.config))
        if attribute_id == 7:
            return _short_string(self.config.model)
        return None

    def identity_all(self) -> bytes:
        return b"".join(
            [
                self.identity_attribute(1) or b"",
                self.identity_attribute(2) or b"",
                self.identity_attribute(3) or b"",
                self.identity_attribute(4) or b"",
                self.identity_attribute(5) or b"",
                self.identity_attribute(6) or b"",
                self.identity_attribute(7) or b"",
            ]
        )

    def point_attribute(self, instance_id: int, attribute_id: int) -> bytes | None:
        point = self.point_instance_map.get(instance_id)
        if point is None:
            return None
        if attribute_id == 1:
            raw = self._read_raw(point)
            return bytes([raw & 0xFF]) if point.is_bool else _u16(raw)
        if attribute_id == 2:
            return _short_string(point.label)
        if attribute_id == 3:
            return _short_string(point.kind)
        if attribute_id == 4:
            return _u16(point.address)
        if attribute_id == 5:
            return bytes([1 if point.writable else 0])
        return None

    def set_point_attribute(self, instance_id: int, attribute_id: int, payload: bytes) -> int:
        point = self.point_instance_map.get(instance_id)
        if point is None:
            return CIP_STATUS_PATH_DESTINATION_UNKNOWN
        if not point.writable:
            return CIP_STATUS_INSUFFICIENT_ACCESS
        if attribute_id != 1:
            return CIP_STATUS_ATTRIBUTE_NOT_SUPPORTED
        if point.is_bool:
            if len(payload) < 1:
                return CIP_STATUS_INVALID_PARAMETER
            raw_value = 1 if payload[0] else 0
        else:
            if len(payload) < 2:
                return CIP_STATUS_INVALID_PARAMETER
            raw_value = struct.unpack_from("<H", payload, 0)[0]
        with self.image.lock:
            self.image.write_raw_point(point, raw_value)
        return CIP_STATUS_SUCCESS

    def assembly_attribute(self, instance_id: int, attribute_id: int) -> bytes | None:
        if attribute_id != 3:
            return None
        if instance_id == ASSEMBLY_OUTPUT_INSTANCE:
            return self._pack_output_assembly()
        if instance_id == ASSEMBLY_INPUT_INSTANCE:
            return self._pack_input_assembly()
        return None

    def set_assembly_attribute(self, instance_id: int, attribute_id: int, payload: bytes) -> int:
        if instance_id != ASSEMBLY_OUTPUT_INSTANCE or attribute_id != 3:
            return CIP_STATUS_ATTRIBUTE_NOT_SUPPORTED
        with self.image.lock:
            coils = sorted((point for point in self.image.device.points if point.kind == "coil"), key=lambda point: point.address)
            holding = sorted(
                (point for point in self.image.device.points if point.kind == "holding_register"),
                key=lambda point: point.address,
            )
            coil_bytes = 0 if not coils else (coils[-1].address // 8) + 1
            if len(payload) < coil_bytes + (len(holding) * 2):
                return CIP_STATUS_INVALID_PARAMETER
            for point in coils:
                byte_offset = point.address // 8
                bit = point.address % 8
                raw_value = 1 if payload[byte_offset] & (1 << bit) else 0
                if point.writable:
                    self.image.write_raw_point(point, raw_value)
            register_offset = coil_bytes
            for point in holding:
                raw_value = struct.unpack_from("<H", payload, register_offset + (point.address * 2))[0]
                if point.writable:
                    self.image.write_raw_point(point, raw_value)
        return CIP_STATUS_SUCCESS

    def produced_udp_payload(self, sequence: int, connection_id: int) -> bytes:
        assembly = self._pack_input_assembly()
        return _pack_cpf(
            [
                (CPF_SEQUENCED_ADDRESS, struct.pack("<IH", connection_id & 0xFFFFFFFF, sequence & 0xFFFF)),
                (CPF_CONNECTED_DATA, struct.pack("<H", sequence & 0xFFFF) + assembly),
            ]
        )

    def _read_raw(self, point) -> int:
        with self.image.lock:
            return self.image.read_raw_point(point)

    def _pack_output_assembly(self) -> bytes:
        coils = sorted((point for point in self.image.device.points if point.kind == "coil"), key=lambda point: point.address)
        holding = sorted(
            (point for point in self.image.device.points if point.kind == "holding_register"),
            key=lambda point: point.address,
        )
        coil_bytes = bytearray(0 if not coils else (coils[-1].address // 8) + 1)
        registers = bytearray((holding[-1].address + 1) * 2 if holding else 0)
        with self.image.lock:
            for point in coils:
                raw = self.image.read_raw_point(point)
                if raw:
                    coil_bytes[point.address // 8] |= 1 << (point.address % 8)
            for point in holding:
                struct.pack_into("<H", registers, point.address * 2, self.image.read_raw_point(point))
        return bytes(coil_bytes + registers)

    def _pack_input_assembly(self) -> bytes:
        discrete = sorted(
            (point for point in self.image.device.points if point.kind == "discrete_input"),
            key=lambda point: point.address,
        )
        inputs = sorted(
            (point for point in self.image.device.points if point.kind == "input_register"),
            key=lambda point: point.address,
        )
        discrete_bytes = bytearray(0 if not discrete else (discrete[-1].address // 8) + 1)
        registers = bytearray((inputs[-1].address + 1) * 2 if inputs else 0)
        with self.image.lock:
            for point in discrete:
                raw = self.image.read_raw_point(point)
                if raw:
                    discrete_bytes[point.address // 8] |= 1 << (point.address % 8)
            for point in inputs:
                struct.pack_into("<H", registers, point.address * 2, self.image.read_raw_point(point))
        return bytes(discrete_bytes + registers)


class CipServer:
    def __init__(self, config: EmulatorConfig, image: ProcessImage):
        self.config = config
        self.image = image
        self.model = CipImageModel(config, image)
        self.sessions: dict[int, EnipSession] = {}
        self.next_session_handle = 1
        self.active_connection: ForwardOpenConnection | None = None
        self.server: asyncio.AbstractServer | None = None
        self.udp_transport: asyncio.DatagramTransport | None = None
        self.udp_task: asyncio.Task[None] | None = None
        self._state_lock = asyncio.Lock()
        self._stop_event = asyncio.Event()

    async def serve(self) -> None:
        loop = asyncio.get_running_loop()
        udp_transport, _ = await loop.create_datagram_endpoint(
            asyncio.DatagramProtocol,
            local_addr=(self.config.host, IMPLICIT_UDP_PORT),
            family=socket.AF_INET,
        )
        self.udp_transport = udp_transport  # type: ignore[assignment]
        self.udp_task = asyncio.create_task(self._udp_producer_loop())
        self.server = await asyncio.start_server(self._handle_client, self.config.host, self.config.port)
        sockets = ", ".join(str(sock.getsockname()) for sock in (self.server.sockets or []))
        log.info(
            "Starting %s backend for '%s' (vendor=%s model=%s) on TCP %s and UDP %s:%d",
            self.config.protocol,
            self.config.name,
            self.config.vendor,
            self.config.model,
            sockets,
            self.config.host,
            IMPLICIT_UDP_PORT,
        )
        try:
            async with self.server:
                await self.server.serve_forever()
        finally:
            self._stop_event.set()
            if self.udp_task is not None:
                self.udp_task.cancel()
                with contextlib.suppress(asyncio.CancelledError):
                    await self.udp_task
            if self.udp_transport is not None:
                self.udp_transport.close()

    async def _udp_producer_loop(self) -> None:
        while not self._stop_event.is_set():
            await asyncio.sleep(0.005)
            async with self._state_lock:
                connection = self.active_connection
                if connection is None or self.udp_transport is None:
                    continue
                now = asyncio.get_running_loop().time()
                if connection.next_due > now:
                    continue
                payload = self.model.produced_udp_payload(connection.sequence, connection.input_connection_id)
                self.udp_transport.sendto(payload, (connection.peer_host, connection.peer_port))
                log.debug(
                    "[%s] CIP implicit I/O push conn=0x%08x seq=%d to %s:%d len=%d",
                    self.config.name,
                    connection.input_connection_id,
                    connection.sequence,
                    connection.peer_host,
                    connection.peer_port,
                    len(payload),
                )
                connection.sequence = (connection.sequence + 1) & 0xFFFF
                connection.next_due = now + connection.rpi_seconds

    async def _handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        peer = writer.get_extra_info("peername")
        log.info("[%s] CIP TCP client connected from %s", self.config.name, peer)
        try:
            while True:
                header = await reader.readexactly(ENIP_HEADER.size)
                command, payload_len, session_handle, status, sender_context, options = ENIP_HEADER.unpack(header)
                payload = await reader.readexactly(payload_len)
                response = await self._dispatch_encapsulation(
                    command=command,
                    session_handle=session_handle,
                    sender_context=sender_context,
                    options=options,
                    payload=payload,
                    peer=peer,
                )
                if response is None:
                    continue
                writer.write(response)
                await writer.drain()
                if command == ENIP_CMD_UNREGISTER_SESSION:
                    break
        except asyncio.IncompleteReadError:
            pass
        finally:
            log.info("[%s] CIP TCP client disconnected from %s", self.config.name, peer)
            writer.close()
            with contextlib.suppress(Exception):
                await writer.wait_closed()

    async def _dispatch_encapsulation(
        self,
        *,
        command: int,
        session_handle: int,
        sender_context: bytes,
        options: int,
        payload: bytes,
        peer: tuple[str, int],
    ) -> bytes | None:
        if command == ENIP_CMD_REGISTER_SESSION:
            handle, data = self._register_session(payload, peer)
            return self._encapsulation_response(command, handle, sender_context, options, data)
        if command == ENIP_CMD_UNREGISTER_SESSION:
            await self._unregister_session(session_handle)
            return None
        if command == ENIP_CMD_LIST_SERVICES:
            return self._encapsulation_response(command, 0, sender_context, options, self._list_services())
        if command == ENIP_CMD_LIST_IDENTITY:
            return self._encapsulation_response(command, 0, sender_context, options, self._list_identity(peer))
        if command == ENIP_CMD_SEND_RR_DATA:
            cip_payload = await self._handle_send_rr_data(session_handle, payload, peer)
            return self._encapsulation_response(command, session_handle, sender_context, options, cip_payload)
        log.warning("[%s] Unsupported EtherNet/IP command 0x%04x from %s", self.config.name, command, peer)
        return self._encapsulation_response(command, session_handle, sender_context, options, b"", status=1)

    def _encapsulation_response(
        self,
        command: int,
        session_handle: int,
        sender_context: bytes,
        options: int,
        payload: bytes,
        *,
        status: int = 0,
    ) -> bytes:
        header = ENIP_HEADER.pack(
            command,
            len(payload),
            session_handle,
            status,
            sender_context[:8].ljust(8, b"\x00"),
            options,
        )
        return header + payload

    def _register_session(self, payload: bytes, peer: tuple[str, int]) -> tuple[int, bytes]:
        if len(payload) < 4:
            return 0, b""
        protocol_version, options_flags = struct.unpack_from("<HH", payload, 0)
        if protocol_version != 1:
            return 0, b""
        handle = self.next_session_handle
        self.next_session_handle += 1
        self.sessions[handle] = EnipSession(handle=handle, peer=peer)
        log.info("[%s] CIP RegisterSession handle=%d peer=%s", self.config.name, handle, peer)
        return handle, struct.pack("<HH", protocol_version, options_flags)

    async def _unregister_session(self, session_handle: int) -> None:
        self.sessions.pop(session_handle, None)
        async with self._state_lock:
            if self.active_connection is not None and self.active_connection.session_handle == session_handle:
                log.info("[%s] CIP implicit connection closed with session %d", self.config.name, session_handle)
                self.active_connection = None

    def _list_services(self) -> bytes:
        version = 1
        capability_flags = 0x0120
        name = b"Communications"
        item = struct.pack("<H", version) + struct.pack("<H", capability_flags) + name.ljust(16, b"\x00")
        return _pack_cpf([(0x0100, item)])

    def _list_identity(self, peer: tuple[str, int]) -> bytes:
        sockaddr = (
            struct.pack(">H", 2)
            + struct.pack(">H", self.config.port)
            + socket.inet_aton(self._response_ip(peer[0]))
            + (b"\x00" * 8)
        )
        identity = bytearray()
        identity.extend(struct.pack("<H", 1))
        identity.extend(struct.pack("<H", 0))
        identity.extend(sockaddr)
        identity.extend(_u16(_vendor_id_from_name(self.config.vendor)))
        identity.extend(_u16(DEVICE_TYPE_PROGRAMMABLE_CONTROLLER))
        identity.extend(_u16(_numeric_product_code(self.config.product_code)))
        identity.extend(bytes([1, 0]))
        identity.extend(_u16(0))
        identity.extend(_u32(_serial_number(self.config)))
        identity.extend(_short_string(self.config.model))
        identity.extend(bytes([0]))
        return _pack_cpf([(CPF_LIST_IDENTITY, bytes(identity))])

    async def _handle_send_rr_data(self, session_handle: int, payload: bytes, peer: tuple[str, int]) -> bytes:
        if session_handle not in self.sessions:
            log.warning("[%s] CIP SendRRData on unknown session %d from %s", self.config.name, session_handle, peer)
            return _pack_rr_data(_response_message(CIP_SERVICE_GET_ATTRIBUTE_SINGLE, CIP_STATUS_OBJECT_STATE_CONFLICT))
        if len(payload) < 8:
            return _pack_rr_data(_response_message(CIP_SERVICE_GET_ATTRIBUTE_SINGLE, CIP_STATUS_INVALID_PARAMETER))
        interface_handle, timeout, item_count = struct.unpack_from("<IHH", payload, 0)
        idx = 8
        items: list[tuple[int, bytes]] = []
        for _ in range(item_count):
            if idx + 4 > len(payload):
                return _pack_rr_data(_response_message(CIP_SERVICE_GET_ATTRIBUTE_SINGLE, CIP_STATUS_INVALID_PARAMETER))
            item_type, item_len = struct.unpack_from("<HH", payload, idx)
            idx += 4
            if idx + item_len > len(payload):
                return _pack_rr_data(_response_message(CIP_SERVICE_GET_ATTRIBUTE_SINGLE, CIP_STATUS_INVALID_PARAMETER))
            items.append((item_type, payload[idx : idx + item_len]))
            idx += item_len
        cip_request = next((data for item_type, data in items if item_type in {CPF_UNCONNECTED_DATA, CPF_CONNECTED_DATA}), None)
        if cip_request is None:
            return _pack_rr_data(_response_message(CIP_SERVICE_GET_ATTRIBUTE_SINGLE, CIP_STATUS_INVALID_PARAMETER))
        response = await self._route_cip_request(session_handle, cip_request, peer)
        return _pack_rr_data(response)

    async def _route_cip_request(self, session_handle: int, request: bytes, peer: tuple[str, int]) -> bytes:
        parsed = _parse_message_router_request(request)
        if parsed is None:
            return _response_message(CIP_SERVICE_GET_ATTRIBUTE_SINGLE, CIP_STATUS_INVALID_PARAMETER)
        service, path, data = parsed
        class_id, instance_id, attribute_id, _segments = _parse_epath(path)
        log.debug(
            "[%s] CIP explicit service=0x%02x class=0x%02x instance=%s attribute=%s peer=%s",
            self.config.name,
            service,
            class_id or 0,
            instance_id,
            attribute_id,
            peer,
        )

        if class_id == CIP_CLASS_IDENTITY and instance_id == 1:
            return self._route_identity(service, attribute_id)
        if class_id == CIP_CLASS_LAB_POINT and instance_id is not None:
            return self._route_point(service, instance_id, attribute_id, data)
        if class_id == CIP_CLASS_ASSEMBLY and instance_id is not None:
            return self._route_assembly(service, instance_id, attribute_id, data)
        if class_id == CIP_CLASS_CONNECTION_MANAGER and instance_id == 1:
            return await self._route_connection_manager(service, session_handle, data, peer)
        return _response_message(service, CIP_STATUS_PATH_DESTINATION_UNKNOWN)

    def _route_identity(self, service: int, attribute_id: int | None) -> bytes:
        if service == CIP_SERVICE_GET_ATTRIBUTE_ALL:
            return _response_message(service, CIP_STATUS_SUCCESS, self.model.identity_all())
        if service == CIP_SERVICE_GET_ATTRIBUTE_SINGLE and attribute_id is not None:
            value = self.model.identity_attribute(attribute_id)
            if value is None:
                return _response_message(service, CIP_STATUS_ATTRIBUTE_NOT_SUPPORTED)
            return _response_message(service, CIP_STATUS_SUCCESS, value)
        return _response_message(service, CIP_STATUS_SERVICE_NOT_SUPPORTED)

    def _route_point(self, service: int, instance_id: int, attribute_id: int | None, data: bytes) -> bytes:
        if attribute_id is None:
            return _response_message(service, CIP_STATUS_ATTRIBUTE_NOT_SUPPORTED)
        if service == CIP_SERVICE_GET_ATTRIBUTE_SINGLE:
            value = self.model.point_attribute(instance_id, attribute_id)
            if value is None:
                return _response_message(service, CIP_STATUS_ATTRIBUTE_NOT_SUPPORTED)
            return _response_message(service, CIP_STATUS_SUCCESS, value)
        if service == CIP_SERVICE_SET_ATTRIBUTE_SINGLE:
            status = self.model.set_point_attribute(instance_id, attribute_id, data)
            return _response_message(service, status)
        return _response_message(service, CIP_STATUS_SERVICE_NOT_SUPPORTED)

    def _route_assembly(self, service: int, instance_id: int, attribute_id: int | None, data: bytes) -> bytes:
        if attribute_id is None:
            return _response_message(service, CIP_STATUS_ATTRIBUTE_NOT_SUPPORTED)
        if service == CIP_SERVICE_GET_ATTRIBUTE_SINGLE:
            value = self.model.assembly_attribute(instance_id, attribute_id)
            if value is None:
                return _response_message(service, CIP_STATUS_ATTRIBUTE_NOT_SUPPORTED)
            return _response_message(service, CIP_STATUS_SUCCESS, value)
        if service == CIP_SERVICE_SET_ATTRIBUTE_SINGLE:
            status = self.model.set_assembly_attribute(instance_id, attribute_id, data)
            return _response_message(service, status)
        return _response_message(service, CIP_STATUS_SERVICE_NOT_SUPPORTED)

    async def _route_connection_manager(
        self,
        service: int,
        session_handle: int,
        data: bytes,
        peer: tuple[str, int],
    ) -> bytes:
        if service == CIP_SERVICE_FORWARD_OPEN:
            return await self._forward_open(service, session_handle, data, peer)
        if service == CIP_SERVICE_FORWARD_CLOSE:
            return await self._forward_close(service, session_handle, data)
        return _response_message(service, CIP_STATUS_SERVICE_NOT_SUPPORTED)

    async def _forward_open(
        self,
        service: int,
        session_handle: int,
        data: bytes,
        peer: tuple[str, int],
    ) -> bytes:
        if len(data) < 35:
            return _response_message(service, CIP_STATUS_INVALID_PARAMETER)
        try:
            output_connection_id = struct.unpack_from("<I", data, 2)[0]
            input_connection_id = struct.unpack_from("<I", data, 6)[0]
            connection_serial = struct.unpack_from("<H", data, 10)[0]
            originator_vendor_id = struct.unpack_from("<H", data, 12)[0]
            originator_serial = struct.unpack_from("<I", data, 14)[0]
            output_rpi = struct.unpack_from("<I", data, 22)[0]
            input_rpi = struct.unpack_from("<I", data, 28)[0]
            transport_type_trigger = data[34]
        except struct.error:
            return _response_message(service, CIP_STATUS_INVALID_PARAMETER)

        async with self._state_lock:
            now = asyncio.get_running_loop().time()
            self.active_connection = ForwardOpenConnection(
                session_handle=session_handle,
                peer_host=peer[0],
                peer_port=IMPLICIT_UDP_PORT,
                output_connection_id=output_connection_id or 0x20000002,
                input_connection_id=input_connection_id or 0x20000001,
                connection_serial=connection_serial,
                originator_vendor_id=originator_vendor_id,
                originator_serial_number=originator_serial,
                requested_packet_interval_us=input_rpi or output_rpi or 100_000,
                opened_monotonic=now,
                transport_type_trigger=transport_type_trigger,
                next_due=now,
            )
        log.info(
            "[%s] CIP ForwardOpen peer=%s conn_serial=%d producer=0x%08x consumer=0x%08x rpi_us=%d udp=%d",
            self.config.name,
            peer,
            connection_serial,
            self.active_connection.input_connection_id if self.active_connection else 0,
            self.active_connection.output_connection_id if self.active_connection else 0,
            self.active_connection.requested_packet_interval_us if self.active_connection else 0,
            IMPLICIT_UDP_PORT,
        )
        response_data = (
            _u32(self.active_connection.output_connection_id)
            + _u32(self.active_connection.input_connection_id)
            + _u16(connection_serial)
            + _u16(originator_vendor_id)
            + _u32(originator_serial)
            + _u32(output_rpi or 100_000)
            + _u32(input_rpi or 100_000)
            + b"\x00\x00"
        )
        return _response_message(service, CIP_STATUS_SUCCESS, response_data)

    async def _forward_close(self, service: int, session_handle: int, data: bytes) -> bytes:
        if len(data) < 12:
            return _response_message(service, CIP_STATUS_INVALID_PARAMETER)
        connection_serial = struct.unpack_from("<H", data, 2)[0]
        originator_vendor_id = struct.unpack_from("<H", data, 4)[0]
        originator_serial = struct.unpack_from("<I", data, 6)[0]
        closed = False
        async with self._state_lock:
            connection = self.active_connection
            if (
                connection is not None
                and connection.session_handle == session_handle
                and connection.connection_serial == connection_serial
                and connection.originator_vendor_id == originator_vendor_id
                and connection.originator_serial_number == originator_serial
            ):
                self.active_connection = None
                closed = True
        if closed:
            log.info("[%s] CIP ForwardClose conn_serial=%d", self.config.name, connection_serial)
            response_data = _u16(connection_serial) + _u16(originator_vendor_id) + _u32(originator_serial)
            return _response_message(service, CIP_STATUS_SUCCESS, response_data)
        return _response_message(service, CIP_STATUS_OBJECT_STATE_CONFLICT)

    def _response_ip(self, peer_host: str) -> str:
        if self.config.host not in {"0.0.0.0", ""}:
            return self.config.host
        return peer_host if "." in peer_host else "127.0.0.1"


@register_protocol("cip")
class CipBackend(ProtocolBackend):
    async def serve(self, config: EmulatorConfig, image: ProcessImage) -> None:
        server = CipServer(config, image)
        await server.serve()

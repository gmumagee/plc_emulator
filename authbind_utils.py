#!/usr/bin/env python3
"""Shared authbind helpers for UI checks and bulk provisioning."""

from __future__ import annotations

import os
import pwd
import shutil
from dataclasses import dataclass
from pathlib import Path

from device_defs import DeviceDefinition, DeviceLoadError, load_device_definitions


DEFAULT_AUTHBIND_DIR = Path("/etc/authbind/byport")
PRIVILEGED_PORT_CUTOFF = 1024
AUTHBIND_FILE_MODE = 0o500


@dataclass(frozen=True)
class AuthbindPortStatus:
    port: int
    path: Path
    available: bool
    privileged: bool
    exists: bool
    owner: str | None
    owner_matches: bool
    mode: int | None
    mode_matches: bool
    configured: bool
    expected_owner: str

    def to_dict(self) -> dict[str, object]:
        return {
            "port": self.port,
            "path": str(self.path),
            "available": self.available,
            "privileged": self.privileged,
            "exists": self.exists,
            "owner": self.owner,
            "owner_matches": self.owner_matches,
            "mode": None if self.mode is None else oct(self.mode),
            "mode_matches": self.mode_matches,
            "configured": self.configured,
            "expected_owner": self.expected_owner,
        }


def authbind_available() -> bool:
    return shutil.which("authbind") is not None


def authbind_dir(authbind_root: Path | None = None) -> Path:
    if authbind_root is not None:
        return authbind_root
    return Path(os.environ.get("AUTHBIND_BYPORT_DIR", str(DEFAULT_AUTHBIND_DIR)))


def effective_authbind_user() -> str:
    sudo_user = os.environ.get("SUDO_USER")
    if sudo_user:
        return sudo_user
    return pwd.getpwuid(os.getuid()).pw_name


def authbind_entry_path(port: int, *, authbind_root: Path | None = None) -> Path:
    return authbind_dir(authbind_root) / str(port)


def get_authbind_port_status(port: int, *, user: str | None = None, authbind_root: Path | None = None) -> AuthbindPortStatus:
    expected_owner = user or effective_authbind_user()
    path = authbind_entry_path(port, authbind_root=authbind_root)
    privileged = 1 <= int(port) < PRIVILEGED_PORT_CUTOFF
    available = authbind_available()

    owner = None
    owner_matches = False
    mode = None
    mode_matches = False
    exists = path.exists()

    if exists:
        stat_result = path.stat()
        owner = pwd.getpwuid(stat_result.st_uid).pw_name
        owner_matches = owner == expected_owner
        mode = stat_result.st_mode & 0o777
        mode_matches = mode == AUTHBIND_FILE_MODE

    configured = available and privileged and exists and owner_matches and mode_matches
    return AuthbindPortStatus(
        port=int(port),
        path=path,
        available=available,
        privileged=privileged,
        exists=exists,
        owner=owner,
        owner_matches=owner_matches,
        mode=mode,
        mode_matches=mode_matches,
        configured=configured,
        expected_owner=expected_owner,
    )


def load_privileged_device_ports(device_dir: Path | None = None) -> tuple[list[int], list[DeviceLoadError]]:
    devices, errors = load_device_definitions(device_dir)
    ports = sorted({device.default_port for device in devices.values() if 1 <= device.default_port < PRIVILEGED_PORT_CUTOFF})
    return ports, errors


def provision_authbind_port(port: int, *, user: str | None = None, authbind_root: Path | None = None) -> AuthbindPortStatus:
    target_user = user or effective_authbind_user()
    pw_entry = pwd.getpwnam(target_user)
    path = authbind_entry_path(port, authbind_root=authbind_root)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.touch(exist_ok=True)
    os.chown(path, pw_entry.pw_uid, -1)
    os.chmod(path, AUTHBIND_FILE_MODE)
    return get_authbind_port_status(port, user=target_user, authbind_root=authbind_root)


def summarize_device_ports(devices: dict[str, DeviceDefinition]) -> list[int]:
    return sorted({device.default_port for device in devices.values() if 1 <= device.default_port < PRIVILEGED_PORT_CUTOFF})

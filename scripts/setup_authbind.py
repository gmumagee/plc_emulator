#!/usr/bin/env python3
"""Bulk-provision authbind byport files for every privileged device port."""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path


PROJECT_DIR = Path(__file__).resolve().parent.parent
if str(PROJECT_DIR) not in sys.path:
    sys.path.insert(0, str(PROJECT_DIR))

from authbind_utils import effective_authbind_user, get_authbind_port_status, load_privileged_device_ports, provision_authbind_port


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Provision authbind files for all privileged device default ports.")
    parser.add_argument("--device-dir", type=Path, default=None, help="Override device definition directory")
    parser.add_argument("--authbind-dir", type=Path, default=None, help="Override authbind byport directory (mainly for testing)")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.authbind_dir is None and os.geteuid() != 0:
        print("This script must be run with sudo/root so it can write /etc/authbind/byport.", file=sys.stderr)
        return 1

    target_user = effective_authbind_user()
    ports, errors = load_privileged_device_ports(args.device_dir)

    if errors:
        print("Device definition validation errors were found. Valid devices were still scanned for privileged ports:")
        for error in errors:
            print(f"  - {error.file}: {error.error}")

    if not ports:
        print("No privileged ports (<1024) were found in the device library. Nothing to provision.")
        return 0

    already_configured: list[int] = []
    provisioned: list[int] = []
    failed: list[str] = []

    print(f"Scanning privileged device ports for authbind setup as user '{target_user}':")
    for port in ports:
        status = get_authbind_port_status(port, user=target_user, authbind_root=args.authbind_dir)
        if status.configured:
            already_configured.append(port)
            print(f"  - {port}: already configured")
            continue
        try:
            status = provision_authbind_port(port, user=target_user, authbind_root=args.authbind_dir)
        except Exception as exc:  # pragma: no cover - operational failure path
            failed.append(f"{port}: {exc}")
            print(f"  - {port}: FAILED ({exc})")
            continue
        if status.configured:
            provisioned.append(port)
            print(f"  - {port}: provisioned")
        else:
            failed.append(
                f"{port}: owner={status.owner!r} expected={status.expected_owner!r} mode={oct(status.mode or 0)}"
            )
            print(f"  - {port}: FAILED (post-check did not pass)")

    print("\nSummary")
    print(f"  already configured: {', '.join(str(port) for port in already_configured) if already_configured else '(none)'}")
    print(f"  newly provisioned: {', '.join(str(port) for port in provisioned) if provisioned else '(none)'}")
    print(f"  failed: {', '.join(failed) if failed else '(none)'}")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())

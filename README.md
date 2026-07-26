# PLC Fleet Control

A protocol-aware device emulator for an isolated ICS lab. Device identity,
process points, simulation behavior, and HMI layout now come from JSON files in
[devices/](/home/mike/projects/plc_em/devices), so adding a new sensor, pump,
gate, RTU, or PLC on an existing backend is a data-only change.

## Protocol support

This repo currently uses a **protocol-shaped** scope: correct ports, believable
traffic, and enough behavior for lab polling/writing and packet dissection,
without attempting full vendor-stack correctness for every service edge case.

| Protocol | Default port | Emulator status | HMI client status | Notes |
| --- | ---: | --- | --- | --- |
| `modbus` | 502 | Implemented | Implemented | Request/response polling |
| `s7comm` | 102 | Implemented | Implemented | `python-snap7` server/client |
| `fins` | 9600 | Implemented | Not implemented | UDP-only, memory area read/write plus unsolicited memory write pushes |
| `cip` | 44818 | Implemented | Not implemented | EtherNet/IP Register Session plus explicit messaging on TCP, `Forward Open` / `Forward Close`, and cyclic implicit I/O pushes on UDP `2222` |
| `mc` | 5007 | Not implemented | Not implemented | Device definitions can reference it, launch is blocked |

Protocol backends are discovered from [protocols/](/home/mike/projects/plc_em/protocols)
with the registration decorator documented in
[protocols/base.py](/home/mike/projects/plc_em/protocols/base.py).

## Setup

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

## Running the app

Run the web UI from the repo root:

```bash
python3 web/app.py --host 127.0.0.1 --port 8080
```

Then open `http://127.0.0.1:8080`.

Register a user at `/register`, then sign in at `/login`.

Run a single emulator directly:

```bash
python3 plc_emulator.py --device-type generic-gc3000 --host 127.0.0.1 --port 5020 --unit-id 1 --name PLC-1
python3 plc_emulator.py --device-type siemens-s71200 --host 127.0.0.1 --port 1102 --name S7-1
```

`--plc-type` is still accepted as a legacy alias for `--device-type`.

Low ports such as `102` and `502` still need root, `authbind`, or equivalent.
The web launcher reuses the existing `authbind` handling automatically.

## User accounts

This build now uses local username/password accounts with:

- password hashing via Werkzeug's `generate_password_hash` / `check_password_hash`
- session management via `Flask-Login`
- CSRF protection on login, logout, and all state-changing saved-config and fleet actions
- a short in-memory failed-login lockout to avoid unthrottled password guessing

Account and saved-config data live in SQLite at
[web/fleet_control.db](/home/mike/projects/plc_em/web/fleet_control.db). That
file is outside [web/static/](/home/mike/projects/plc_em/web/static), so it is
not exposed as a static download by the Flask app.

Saved device configs are scoped to the logged-in user only. Each user sees and
manages only their own saved library. Live fleet instances remain shared and
visible to every authenticated user on the lab segment so everyone can still
see what is actually running on the wire.

Important security note: authentication over plain HTTP is not enough. If you
use real logins, run this behind HTTPS so usernames, passwords, and session
cookies are not sent in cleartext. A reverse proxy with a certificate, even a
self-signed lab certificate, is the minimum sane deployment once credentials
exist.

## Bulk-Provisioning authbind

To provision every privileged port referenced by the current device library in one pass, run:

```bash
sudo ./dev/bin/python scripts/setup_authbind.py
```

This script scans [devices/](/home/mike/projects/plc_em/devices) with the same
device loader used by the app, collects every unique `default_port` below
`1024`, and provisions `/etc/authbind/byport/<port>` entries only where they
are missing or misconfigured for the current user.

Use it so a lab operator does not have to hand-run the `touch` / `chown` /
`chmod` sequence every time a new device definition introduces a new low port.
Re-run it after pulling new device definitions from version control, for
example after a `git pull` that adds new files under `devices/`, because a new
privileged port will fail to launch until authbind has been provisioned for it.

Running the script twice is safe: the second run is a no-op and reports already
configured ports as skipped.

## Device definitions

Each file under [devices/](/home/mike/projects/plc_em/devices) defines one
device type. The web UI serves them through `GET /api/device-types`, and both
[plc_emulator.py](/home/mike/projects/plc_em/plc_emulator.py) and
[hmi_client.py](/home/mike/projects/plc_em/hmi_client.py) resolve the selected
device from the same loader in [device_defs.py](/home/mike/projects/plc_em/device_defs.py).

Schema shape:

```json
{
  "id": "siemens-s7-1200-tank",
  "vendor": "Siemens",
  "model": "S7-1200",
  "device_class": "plc",
  "protocol": "s7comm",
  "default_port": 102,
  "product_code": "6ES7 212-1AE40-0XB0",
  "simulation": {
    "type": "tank_pump_valve",
    "params": {
      "fill_rate": 8.0,
      "drain_rate": 6.0
    }
  },
  "points": [
    {
      "id": "pump_run",
      "label": "Pump",
      "kind": "coil",
      "address": 0,
      "access": "rw",
      "hmi": {
        "widget": "toggle",
        "on_label": "Running",
        "off_label": "Stopped"
      }
    }
  ]
}
```

Top-level fields:

- `id`: stable identifier used by the CLI, API, and registry
- `vendor`, `model`, `product_code`: identity strings shown in cards and exposed by supported protocols
- `device_class`: high-level category such as `plc`, `sensor`, `pump`, `gate`, `rtu`, `ied`
- `protocol`: backend name, matched against registered protocol modules
- `default_port`: suggested launch port in the UI
- `simulation`: one of the built-in simulation modes below
- `points`: the device’s addressable telemetry and controls
- `points[].fault`: optional fault-injection capabilities for that point

Malformed JSON files are rejected individually. They show up in
`GET /api/device-types` under `errors` instead of crashing the whole app.

Point-level fault schema:

```json
{
  "id": "level",
  "label": "Level",
  "kind": "input_register",
  "address": 0,
  "access": "ro",
  "hmi": { "widget": "gauge" },
  "fault": {
    "modes": ["freeze", "drift", "noise"]
  }
}
```

Supported fault modes:

- `freeze`: the reported point value holds its last value while the underlying simulation keeps changing
- `drift`: the reported point value diverges from the true value over time
- `noise`: random jitter is added to the reported point value
- `stuck_actuator`: a writable point acknowledges writes but the physical simulation does not follow them

## Built-in simulation types

The loader currently supports four built-in simulation modes:

- `static`: values stay at their current or initial state unless a writable point is changed externally
- `random_walk`: numeric telemetry drifts within configured bounds, useful for standalone sensors
- `tank_pump_valve`: the existing tank physics model, now parameterized by device JSON
- `actuator_feedback`: writable actuator commands drive derived read-only feedback without a full tank model

Examples in this repo:

- [devices/level-sensor.json](/home/mike/projects/plc_em/devices/level-sensor.json) uses `random_walk`
- [devices/inlet-pump.json](/home/mike/projects/plc_em/devices/inlet-pump.json) uses `actuator_feedback`
- [devices/discharge-gate.json](/home/mike/projects/plc_em/devices/discharge-gate.json) uses `static`
- the vendor PLC presets use `tank_pump_valve`

## Point kinds and protocol mapping

Generic point kinds currently supported by the shared runtime:

- `coil`
- `discrete_input`
- `holding_register`
- `input_register`

How implemented backends map them:

- `modbus`: direct Modbus/TCP coils, discrete inputs, holding registers, and input registers
- `s7comm`: control bits/registers live in DB2, process telemetry lives in DB1, and an engineering text snapshot is exposed in DB900
- `fins`: UDP memory-area commands `0101` and `0102`; `coil` maps to CIO bit area `0x30`, `discrete_input` to WR bit area `0x31`, `holding_register` to DM word area `0x82`, and `input_register` to WR word area `0xB1`
- `cip`: EtherNet/IP explicit messaging exposes the standard Identity object plus a lab point object class `0x70` where each point instance exposes attribute `1` as its raw value; Assembly instance `100` packs writable coils/registers and Assembly instance `101` packs read-only discrete inputs/input registers for cyclic UDP production

FINS backend scope:

- transport: FINS/UDP on port `9600`
- implemented commands: `0101` Memory Area Read and `0102` Memory Area Write
- unsolicited behavior: the emulator sends periodic unsolicited `0102` memory writes for read-only telemetry to the last peer that successfully polled it
- fallback when no peer has polled yet: unsolicited sends are suppressed until the emulator has seen a valid inbound FINS request
- out of scope in this pass: FINS/TCP and the broader Omron command set beyond memory-area access

CIP backend scope:

- transport: EtherNet/IP encapsulation on TCP `44818` plus implicit I/O production on UDP `2222`
- implemented encapsulation commands: `Register Session`, `Unregister Session`, `List Services`, `List Identity`, and `SendRRData`
- implemented CIP services: `Get Attribute All`, `Get Attribute Single`, `Set Attribute Single`, `Forward Open`, and `Forward Close`
- explicit object model: Identity object class `0x01`, Assembly object class `0x04`, Connection Manager class `0x06`, and a lab point object class `0x70` for per-point reads and writes
- cyclic behavior: after a successful `Forward Open`, the emulator pushes the current produced assembly to the originator over UDP at the negotiated RPI without waiting for a read request each cycle
- verification used in this repo: `cpppo` client reads and writes explicit attributes successfully; a raw EtherNet/IP client script was used to verify `Forward Open`, repeated UDP I/O packets, and `Forward Close`
- out of scope in this pass: full CIP object-model correctness, large `Forward Open`, connected explicit messaging, and originator-consumed UDP writes back into the emulator

The runtime stores engineering values internally and converts to raw wire values
with each point’s `scale`. For example, `scale: 0.1` means a raw register value
of `523` is rendered as `52.3`.

## HMI widget vocabulary

The web HMI and `hmi_client.py` are driven from `points[].hmi.widget`.

Supported widgets:

- `toggle`: two-state writable control rendered as paired buttons
- `setpoint`: numeric writable control with explicit Apply-button semantics
- `gauge`: large read-only numeric display
- `readout`: compact read-only value tile
- `alarm_bits`: bitfield decoded into labeled alarm pills

If a point omits `hmi`, it is still exposed on the wire but not rendered in the
operator HMI.

## HMI simulation

Each HMI is a separate client subprocess started on demand from a device card.
It does not read emulator memory directly. It:

- polls the target over the real protocol client
- writes operator actions back over the same protocol
- writes a status JSON file for the web UI to render
- logs its own poll and command activity

Current HMI client support:

- `modbus`
- `s7comm`

Runtime files:

- status snapshots: [web/hmi_status/](/home/mike/projects/plc_em/web/hmi_status)
- command queues: [web/hmi_commands/](/home/mike/projects/plc_em/web/hmi_commands)
- HMI logs: [web/hmi_logs/](/home/mike/projects/plc_em/web/hmi_logs)

## Fault injection

The emulator can now inject live process and sensor faults into a running
instance without restarting it. This is deliberately separate from the
student-facing fleet cards: active faults are not shown inline on the normal
device list, so they remain discoverable by observing real protocol traffic and
process behavior instead of by spotting a UI badge.

Control surface:

- top bar: `Exercise Setup`
- API: `POST /api/instances/<id>/fault`
- API: `POST /api/instances/<id>/fault/clear`
- API: `GET /api/instances/<id>/faults`

Each PLC process gets:

- a fault command queue under [web/fault_commands/](/home/mike/projects/plc_em/web/fault_commands)
- a fault status file under [web/fault_status/](/home/mike/projects/plc_em/web/fault_status)

Example fault request:

```json
{
  "point": "level",
  "mode": "freeze",
  "params": {}
}
```

Behavior notes:

- `freeze`, `drift`, and `noise` affect the value clients read from the device, not the underlying process model
- `stuck_actuator` keeps protocol acknowledgments normal while the actual simulation ignores the command, so the anomaly is only visible by comparing commanded state against derived physical behavior

Worked lab example:

1. Start a tank-model device and confirm `level` rises normally.
2. Open `Exercise Setup`, target that instance, and inject `freeze` on `level`.
3. Poll the PLC with a real client and observe that `level` stops changing even though `uptime` and the rest of the process continue.
4. Clear the fault and observe the reported `level` jump back to the real process state.
5. Inject `stuck_actuator` on `pump_run`, write the pump coil off from a client, and observe that the write succeeds while flow and tank behavior prove the process never obeyed it.

## Adding a new device

### Existing protocol backend

If the new device uses an existing backend, add one JSON file to
[devices/](/home/mike/projects/plc_em/devices) and restart the web app. No JS or
Python code changes should be required.

Worked example: [devices/inlet-pump.json](/home/mike/projects/plc_em/devices/inlet-pump.json)

- `device_class` is `pump`
- `simulation.type` is `actuator_feedback`
- `pump_run` is a writable `toggle`
- `pump_speed` is a writable `setpoint`
- `flow_rate` is a read-only `readout`
- `motor_status` is an `alarm_bits` field

That one file is enough for the device to:

- appear in the device dropdown
- launch on the Modbus backend
- expose the declared points on the wire
- render an HMI with the right controls and feedback

### New protocol backend

If the new device needs a genuinely new protocol:

1. Add a backend module under [protocols/](/home/mike/projects/plc_em/protocols) and register it with `@register_protocol(...)`.
2. Follow the backend contract documented in [protocols/base.py](/home/mike/projects/plc_em/protocols/base.py).
3. Reference that protocol name from one or more device JSON files in [devices/](/home/mike/projects/plc_em/devices).

`plc_emulator.py` discovers registered backends automatically. No manual
dispatcher edits are required.

## Safety note

These emulators bind network listeners and intentionally generate ICS protocol
traffic. Keep them on an isolated lab segment or management-only interface, not
on a network with a route to production or the internet. The new login system
protects access to the UI, but it does not replace network isolation, and it is
only meaningful when the app is served over HTTPS.

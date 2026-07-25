# PLC Fleet Control

A protocol-aware PLC emulator for an isolated ICS security testbed. It keeps
the original Modbus/TCP simulator and now adds a Siemens S7comm backend with a
shared process-simulation core, so traffic on the wire matches the selected
backend instead of only changing cosmetic vendor strings.

PLC identity presets now live in a single registry file, [plc_types.json](/home/mike/projects/plc_em/plc_types.json), and protocol backends are loaded as plugins from [protocols/](/home/mike/projects/plc_em/protocols).

## Protocol support

This build uses a **protocol-shaped** scope decision: real ports, believable
traffic shape, and enough server behavior for common lab tooling to decode and
interact with the protocol, without attempting full vendor-stack fidelity for
every edge case.

| Vendor family | Protocol | Default port | Fidelity in this build | Status |
| --- | --- | ---: | --- | --- |
| Generic Controls Inc. | Modbus/TCP | 502 / 5020 CLI default | Existing request/response polling backend | Implemented |
| Schneider Electric (older M221/M241/M251 style mapping) | Modbus/TCP | 502 | Same Modbus backend, vendor/model identity changes only | Implemented |
| Siemens | S7comm | 102 | Real `python-snap7` server, DB reads/writes, full DB transfer for engineering-style burst traffic | Implemented |
| Allen-Bradley | EtherNet/IP + CIP | 44818 / 2222 | Planned, not shipped in this pass | Not implemented |
| Omron | FINS | 9600 | Planned, not shipped in this pass | Not implemented |
| Mitsubishi Electric | MC Protocol | 5007 | Planned, not shipped in this pass | Not implemented |

The web UI exposes the planned vendor-to-protocol mappings and default ports,
but blocks launch for protocol backends that are not implemented in this
revision instead of silently falling back to Modbus.

For HMI simulation, this build currently implements real protocol clients for
the shipped PLC backends:

- `modbus`
- `s7comm`

Planned PLC protocols without a shipped HMI client yet (`cip`, `fins`, `mc`)
are reported explicitly as unsupported instead of falling back to fake local
state.

## Setup

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

Dependencies currently used by shipped backends:

- `pymodbus==3.8.6` for Modbus/TCP
- `python-snap7==3.1.0` for the Siemens S7 server
- `flask>=3.0,<4.0` for the fleet UI

## PLC registry and backend plugins

[plc_types.json](/home/mike/projects/plc_em/plc_types.json) is the source of
truth for:

- vendor string
- model string
- protocol backend name
- default port
- product code

Both the web UI and `plc_emulator.py` read this same file. Adding a new
vendor/model on an existing protocol is a data change, not a JS/Python code
change.

Protocol implementations live under [protocols/](/home/mike/projects/plc_em/protocols):

- [protocols/base.py](/home/mike/projects/plc_em/protocols/base.py) documents the backend contract
- [protocols/__init__.py](/home/mike/projects/plc_em/protocols/__init__.py) auto-discovers modules and registers them with `@register_protocol(...)`
- adding a new `protocols/<name>.py` module makes that backend available without editing the dispatcher in [plc_emulator.py](/home/mike/projects/plc_em/plc_emulator.py)

## Running a single emulator

Protocol can be selected explicitly with `--protocol`:

```bash
python3 plc_emulator.py --protocol modbus --host 0.0.0.0 --port 5020 --unit-id 1 --name PLC-1
python3 plc_emulator.py --protocol s7comm --host 0.0.0.0 --port 102  --name S7-PLC-1 --vendor Siemens --model S7-1500
```

Or resolve everything from a registry preset with `--plc-type`:

```bash
python3 plc_emulator.py --plc-type generic-gc3000 --host 0.0.0.0 --port 5020 --unit-id 1 --name PLC-1
python3 plc_emulator.py --plc-type siemens-s71500 --host 0.0.0.0 --port 102 --name S7-PLC-1
```

If you omit `--protocol`, the emulator derives it from the vendor string:

- `Generic Controls Inc.` and `Schneider Electric` -> `modbus`
- `Siemens` -> `s7comm`
- all other vendors currently resolve to their native protocol names, but the
  process exits with an explicit "not implemented" error in this build

Default ports by protocol:

- `modbus` -> `5020` from the CLI to avoid low-port privilege requirements by default
- `s7comm` -> `102`
- `cip` -> `44818`
- `fins` -> `9600`
- `mc` -> `5007`

Use low ports such as `502` or `102` with root, `authbind`, or
`setcap cap_net_bind_service+ep $(which python3)` as appropriate for your lab.

## Shared process model

All implemented backends expose the same simulated process:

- inlet pump run command
- outlet valve command
- level setpoint
- pump speed setpoint
- current tank level
- current inlet flow
- alarm word
- uptime

The physics loop models a single tank:

- pump flow increases level according to the speed setpoint
- opening the valve drains the tank
- high/low float switches trip at 90% / 10%
- values update continuously in the background so polling clients see changing telemetry

## Modbus/TCP map

The Modbus backend preserves the original addressing model.

### Coils

- `0` `PUMP_RUN`
- `1` `VALVE_OPEN`
- `2` `ALARM_ACK`

### Discrete inputs

- `0` `LEVEL_HIGH_SW`
- `1` `LEVEL_LOW_SW`
- `2` `E_STOP`

### Holding registers

- `0` `LEVEL_SETPOINT` (0-1000 => 0.0-100.0%)
- `1` `PUMP_SPEED_SP` (0-100)
- `2` `SCAN_TIME_MS`

### Input registers

- `0` `TANK_LEVEL`
- `1` `FLOW_RATE`
- `2` `ALARM_WORD`
- `3` `UPTIME_S`

Quick test:

```python
from pymodbus.client import ModbusTcpClient

c = ModbusTcpClient("127.0.0.1", port=5020)
c.connect()
print(c.read_input_registers(0, count=4, slave=1).registers)
c.write_coil(1, True, slave=1)
c.close()
```

## Siemens S7comm map

The Siemens backend uses the pure-Python `python-snap7` server on TCP port
`102` by default. It exposes three DBs:

### DB1: process telemetry

- `DB1.DBW0` tank level (`LEVEL_X10`)
- `DB1.DBW2` flow rate (`FLOW_X10`)
- `DB1.DBW4` alarm word
- `DB1.DBW6` uptime seconds
- `DB1.DBX8.0` high-level switch
- `DB1.DBX8.1` low-level switch
- `DB1.DBX8.2` e-stop

### DB2: operator controls

- `DB2.DBX0.0` pump run command
- `DB2.DBX0.1` valve open command
- `DB2.DBX0.2` alarm acknowledge pulse
- `DB2.DBW2` level setpoint
- `DB2.DBW4` pump speed setpoint
- `DB2.DBW6` cosmetic scan time

### DB900: engineering transfer block

- `4096` bytes
- starts with ASCII metadata plus current process values
- intended for full-DB transfers so exercises can generate a large burst that
  looks like engineering-station activity

Quick test with `python-snap7`:

```python
import snap7

client = snap7.Client()
client.connect("127.0.0.1", 0, 0, tcp_port=1102)  # use 102 if you bound the native port
print(client.db_read(1, 0, 10))
print(len(client.db_get(900)))
client.disconnect()
client.destroy()
```

## Web control panel

Run the fleet UI:

```bash
python3 web/app.py --host 127.0.0.1 --port 8080
```

Open `http://127.0.0.1:8080`.

What the UI now does:

- fetches PLC presets from `GET /api/plc-types`
- shows a single `PLC type` dropdown built from the shared registry
- resolves the implied protocol backend and default port from the selected preset
- allows optional vendor/model/product-code overrides for intentionally skewed fingerprints without changing the backend
- blocks launch for presets whose backend module is not installed
- stores the selected `plc_type` in `instances.json` while still loading older entries that only have vendor/model/protocol fields
- adds a per-PLC `Open HMI` action that launches a separate protocol client subprocess on demand

## HMI simulation

Each HMI is a standalone client process started by
[hmi_client.py](/home/mike/projects/plc_em/hmi_client.py). It does not read the
PLC emulator's in-memory state directly. Instead, it:

- polls the target PLC over the real wire protocol on a timer
- translates operator actions into real protocol writes
- writes a JSON status snapshot for the web UI to render
- keeps its own subprocess log so HMI traffic is inspectable separately from the PLC log

Current HMI client support:

- Modbus/TCP via `pymodbus`
- Siemens S7comm via `python-snap7`
- CIP / FINS / MC are not implemented on the HMI side in this revision

How to launch one:

- start a PLC from the fleet view
- click `Open HMI` on that PLC card
- the UI opens an inline HMI panel and begins polling `GET /api/hmi/<id>/status`

The HMI panel sends commands back through `POST /api/hmi/<id>/command`. The web
app uses a small file-backed command queue instead of a per-HMI HTTP listener:

- `web/hmi_commands/<hmi_id>.jsonl` receives operator commands from Flask
- the HMI subprocess polls that queue and performs the real protocol write

This was chosen to stay aligned with the existing subprocess/log/status-file
model and avoid allocating an extra listener port for every HMI instance.

Files written by the HMI subsystem:

- logs: [web/hmi_logs](/home/mike/projects/plc_em/web/hmi_logs)
- status JSON for the UI: [web/hmi_status](/home/mike/projects/plc_em/web/hmi_status)
- command queue files: [web/hmi_commands](/home/mike/projects/plc_em/web/hmi_commands)

Lifecycle behavior:

- stopping a PLC while its HMI is still running leaves the HMI up, and it reports a clear degraded/unreachable state from its next failed poll
- deleting a PLC cascades to any attached HMI, stopping and removing the HMI automatically

Implementation note:

- `web/app.py` now launches the emulator with the same Python interpreter that
  started the web app (`sys.executable`), so the subprocess uses the active venv
  instead of assuming a global `python3` with the right packages installed

## Verification completed in this build

Verified locally on Friday, July 24, 2026:

- Modbus backend still answers `pymodbus` reads and writes
- S7 backend answers `python-snap7` DB reads
- S7 backend serves the large `DB900` transfer block via `db_get(900)`
- web-created Siemens instances launch with `--protocol s7comm` and can be read
  by a real `python-snap7` client
- the web UI reads `/api/plc-types` instead of a hardcoded vendor/model map
- a new preset-only entry (`schneider-m262`) appears in the UI with no frontend code changes
- the example [protocols/stublog.py](/home/mike/projects/plc_em/protocols/stublog.py) backend is auto-discovered without editing [plc_emulator.py](/home/mike/projects/plc_em/plc_emulator.py)
- legacy `instances.json` entries without `plc_type` are backfilled from vendor/model/protocol on load
- a web-launched Modbus HMI reaches `connected` state, produces live snapshots, and drives real PLC writes through `POST /api/hmi/<id>/command`
- stopping the target PLC leaves the HMI running but moves it into a degraded/unreachable state
- deleting a PLC cascades to its attached HMI and removes the HMI registry entry

Packet capture note:

- loopback `tcpdump` capture was attempted to verify live HMI polling/write
  traffic on the wire, but this environment denied capture permissions on
  `lo`, so Wireshark/tcpdump verification was not completed here

## Safety note

These emulators bind network listeners and intentionally generate ICS protocol
traffic. Keep them on an isolated lab segment or management-only interface, not
on a network with a route to production or the internet.

## Adding a new PLC type

### Existing protocol backend

If the new PLC uses an already-implemented protocol, edit
[plc_types.json](/home/mike/projects/plc_em/plc_types.json) only:

```json
"schneider-m262": {
  "vendor": "Schneider Electric",
  "model": "Modicon M262",
  "protocol": "modbus",
  "default_port": 502,
  "product_code": "TM262L10MESE8T"
}
```

Restart the web app and the new preset will appear automatically in the `PLC
type` dropdown. The emulator CLI can also launch it directly with
`--plc-type schneider-m262`.

### New protocol backend

If the new PLC needs a genuinely new protocol:

1. Create `protocols/<name>.py`.
2. Implement a class with `async def serve(config, image)`.
3. Decorate it with `@register_protocol("<name>")`.
4. Add one or more entries to `plc_types.json` that reference that protocol name.

Use [protocols/modbus.py](/home/mike/projects/plc_em/protocols/modbus.py),
[protocols/s7comm.py](/home/mike/projects/plc_em/protocols/s7comm.py), and
[protocols/base.py](/home/mike/projects/plc_em/protocols/base.py) as the
template.

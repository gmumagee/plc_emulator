# PLC Emulator (Modbus/TCP)

A software "PLC" for a controlled ICS security testbed. It speaks real
Modbus/TCP on the wire and runs a small simulated tank-level process in the
background so register values move over time like a real controller's would.
Every read/write that hits it is logged.

Tested against **pymodbus 3.8.6** - pinned in `requirements.txt` on purpose,
since pymodbus 3.9+ deprecates/breaks the synchronous datastore API this
script uses.

## Setup

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

## Run a single emulated PLC

```bash
python3 plc_emulator.py --host 0.0.0.0 --port 5020 --unit-id 1 --name PLC-1
```

- Use `--port 502` to bind the standard Modbus port (needs root or
  `setcap cap_net_bind_service+ep $(which python3)`), so the traffic looks
  exactly like a real device to anything sniffing the segment.
- Add `-v` for per-scan-cycle / per-read debug logging.

## Populate a segment with multiple PLCs

Run several instances, e.g. bound to different IPs you've aliased onto the
lab NIC, or differentiated by port/unit-id:

```bash
python3 plc_emulator.py --host 10.10.10.11 --port 502 --name PLC-1 --vendor "Schneider-ish" --model "M221-sim" &
python3 plc_emulator.py --host 10.10.10.12 --port 502 --name PLC-2 --vendor "AB-ish"        --model "MicroLogix-sim" &
python3 plc_emulator.py --host 10.10.10.13 --port 502 --name PLC-3 --unit-id 3 &
```

Varying `--vendor`/`--model`/`--product-code` changes what shows up in the
Modbus device-identification response (function code 0x2B/0x0E), which is
useful if you want your students'/red-team tools' fingerprinting output to
look more like a mixed real-world segment instead of three identical boxes.

## Talking to it

Any Modbus/TCP client or scanner works - `pymodbus`'s own client, `mbtget`,
`modbus-cli`, Wireshark's Modbus dissector for traffic capture, or ICS
scanning/attack tools you already use in the lab (e.g. things that fingerprint
via device identification, or hammer coils/registers to look for
input-validation issues).

Quick manual test:

```python
from pymodbus.client import ModbusTcpClient
c = ModbusTcpClient('10.10.10.11', port=502)
c.connect()
print(c.read_input_registers(0, count=4, slave=1).registers)  # live process values
c.write_coil(1, True, slave=1)                                # open the drain valve
c.close()
```

## Extending it

- **Register map / process model**: everything is in `plc_emulator.py`.
  `run_physics()` is the only function you need to touch to model a
  different process (conveyor, multi-tank, batch sequencer, PID loop,
  whatever the exercise calls for). The Modbus plumbing doesn't change.
- **Other protocols**: if you want traffic beyond Modbus (S7comm, EtherNet/IP
  CIP, DNP3, BACnet) for a more heterogeneous segment, those need different
  libraries per protocol - happy to help build one of those next if useful.
- **Fault injection for defenders to catch**: you could add a `--chaos` mode
  that occasionally writes "wrong" values or drops connections, to give
  students something to detect.
- **Logging**: currently goes to stdout via Python's `logging` module - point
  it at a file/syslog by changing `logging.basicConfig` if you want it to
  feed a SIEM or a pcap-correlation exercise.

## Safety note

This binds a network listener and will happily accept whatever traffic
reaches it. Keep it on the isolated lab segment / air-gapped range - don't
expose it on a network with a route to production or the internet.

# OCPP Log Generator

The script reads Open Charge Point Protocol (OCPP) packets and outputs their contents to a log file, which can be used for troubleshooting.

There are two modes supported:
- **ONLINE**: This mode continiously captures packets from an interface that should be manually specified. Each TCP packet will be passed through a Python Scapy pipeline engine, which will heuristically identify whether it has a WebSocket payload. If masked, the WebSocket payload will be unmasked, and then saved to a timestamped log file using the Python logging facility.
- **OFFLINE**: Does the same procedure, but reads pcaps instead.

Regardless of the mode, the output logs are generated in the `./output-logs` directory (relevant to the `logGenerator.py` location).

Any input pcaps for the offline mode should be placed in the `./pcaps` directory (relevant to the `logGenerator.py` location).

The OCPP Log Generator must be configured by creating a file named `config.ini` with the following structure:

```ini
[Settings]

OperationMode=OFFLINE
#OperationMode=ONLINE
OfflineFiles=monitor.pcap
CaptureInterface=eth1
```

- `OperationMode` can be specified as either `OFFLINE` or `ONLINE`.
- If `OperationMode=OFFLINE`, then `OfflineFiles` must also be specified.
- One or multiple filenames can be assigned to `OfflineFiles`, separated by semicolon. For example, `OfflineFiles=monitor.pcap` or `OfflineFiles=monitor1.pcap;monitor2.pcap`.
- `CaptureInterface` specified the interface used for capturing packets (only in online mode). 
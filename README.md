# OCPP Log Generator

The script reads Open Charge Point Protocol (OCPP) packets and outputs their contents to a log file, which can be used for troubleshooting.

There are two modes supported:
- **ONLINE**: This mode continiously captures packets from an interface that should be manually specified. Each TCP packet will be passed through a Python Scapy pipeline engine, which will heuristically identify whether it has a WebSocket payload. If masked, the WebSocket payload will be unmasked, and then saved to a timestamped log file using the Python logging facility.
- **OFFLINE**: Does the same procedure, but reads pcaps instead.

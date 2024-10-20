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
OfflineFiles=monitor.pcap

#OperationMode=ONLINE
CaptureInterface=eth1
OnlineKafkaMode=0
OnlineKafkaMode_Host=X.X.X.X
OnlineKafkaMode_Port=9092
OnlineKafkaMode_Topic=XXX
OnlineKafkaMode_TLS=0
OnlineKafkaMode_CA=./kafka_certs/CA.pem
OnlineKafkaMode_Cert=./kafka_certs/cert.pem
OnlineKafkaMode_Key=./kafka_certs/key.pem
OnlineKafkaMode_Password=XXX
```

- `OperationMode` can be specified as either `OFFLINE` or `ONLINE`.
- If `OperationMode=OFFLINE`, then `OfflineFiles` must also be specified.
- One or multiple filenames can be assigned to `OfflineFiles`, separated by semicolon. For example, `OfflineFiles=monitor.pcap` or `OfflineFiles=monitor1.pcap;monitor2.pcap`.
- `CaptureInterface` specifies the interface used for capturing packets (only in online mode). 
- `OnlineKafkaMode` can be used to activate the sending of each log line to a Kafka server (only available in online mode).
- `OnlineKafkaMode_*` variables must be used to configure the Kafka connection. If SSL is activated by setting `OnlineKafkaMode_TLS=1`, then the CA, cert, key and password parameters must be set.
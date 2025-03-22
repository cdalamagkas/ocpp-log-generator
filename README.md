# OCPP Log Generator

The script reads Open Charge Point Protocol (OCPP) packets and outputs their contents to a log file, which can be used for troubleshooting.

There are two modes supported:
- **ONLINE**: This mode continiously captures packets from an interface that should be manually specified. Each TCP packet will be passed through a Python Scapy pipeline engine, which will heuristically identify whether it has a WebSocket payload. If masked, the WebSocket payload will be unmasked, and then saved to a timestamped log file using the Python logging facility.
- **OFFLINE**: Does the same procedure, but reads pcaps instead.

Regardless of the mode, the output logs are generated in the `./output-logs` directory (relevant to the `logGenerator.py` location).

Any input pcaps for the offline mode should be placed in the `./pcaps` directory (relevant to the `logGenerator.py` location).

The OCPP Log Generator must be configured by creating a file named `config.json` with the following structure:

```json
{
    "General": {
        "OPERATION_MODE": "ONLINE",
        "ONLINE_CAPTURE_INTERFACE": "ens19",
        "OFFLINE_PCAP_FILES": [],
        "OUTPUT_MODULES": ["LOGSTASH_HTTP", "KAFKA"]
    },
    "KAFKA": {
        "KAFKA_HOST": "***",
        "KAFKA_PORT": 9092,
        "KAFKA_TOPIC": "UC1.ocpploggenerator.logs",
        "KAFKA_SECURITY": "SASL_PLAINTEXT",
	    "KAFKA_SASL_USERNAME": "***",
	    "KAFKA_SASL_PASSWORD": "***",
        "KAFKA_CA": "./certs/CA.pem",
        "KAFKA_CERT": "./certs/cert.pem",
        "KAFKA_KEY": "./certs/key.pem",
        "KAFKA_PASSWORD": "***"
    },
    "LOGSTASH_HTTP": {
        "HOST": "192.168.21.45",
        "PORT": 5958,
        "USERNAME": "***",
        "PASSWORD": "***",
        "CA_CERT": "./certs/ca.crt"
    }
}
```

- `OPERATION_MODE` can be specified as either `OFFLINE` or `ONLINE`.
- If `OPERATION_MODE` is `OFFLINE`, then `OFFLINE_PCAP_FILES` must also be specified.
- One or multiple filenames can be specified in the `OFFLINE_PCAP_FILES` list. For example, `"OFFLINE_PCAP_FILES": [monitor.pcap]` or `"OFFLINE_PCAP_FILES": [monitor1.pcap, monitor2.pcap]`.
- `ONLINE_CAPTURE_INTERFACE` specifies the interface used for capturing packets (only in online mode). 
- `OUTPUT_MODULES` can be used to activate the sending of each log line to one or multiple output modules (only available in online mode).
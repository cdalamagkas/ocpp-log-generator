from scapy.all import *
from datetime import datetime
import logging
from logging.handlers import RotatingFileHandler
import json
import configparser
from pathlib import Path
import math


#### LOGGING CONFIGURATION ###################
class TimestampFilter(logging.Filter):
    def filter(self, record):
        if hasattr(record, 'timestamp'):
            record.created = record.timestamp
        return True

LOG_FILENAME = datetime.now().strftime("%Y%m%d-%H%M%S") + "_ocppLogs.json"
FORMAT = '%(asctime)s.%(msecs)03dZ %(message)s'
DATEFMT = '%Y-%m-%dT%H:%M:%S'
formatter = logging.Formatter(fmt=FORMAT, datefmt=DATEFMT)
logging.basicConfig(format=FORMAT, level=logging.INFO, datefmt=DATEFMT)
LOGGER = logging.getLogger("Rotating Log")
filter = TimestampFilter()
LOGGER.addFilter(filter)
handler = RotatingFileHandler("./output-logs/" + LOG_FILENAME, maxBytes=15728640, backupCount=5)
handler.setFormatter(formatter)
LOGGER.addHandler(handler)

# FRAGMENTATION
Fragmentation = {
    "Fragments": [],
    "More_Fragments": False,
    "Total_Fragments": 0,
    "SrcIP": None,
    "SrcPort": None,
    "DstIP": None,
    "DstPort": None,
    "Masked": False
}


def unmask(payload, mask, offset):
    unmasked = []
    i = 0
    for byte in payload[offset:]:
        byte_unmasked = byte ^ mask[ i % 4 ]
        unmasked.append(byte_unmasked)
        i = i+1
    unmasked = bytearray(unmasked)
    return unmasked


def analysePacketOCPP(packet):
    try:
        payload = packet["IP"]["TCP"].payload.load
    except AttributeError or IndexError:
        #print("Packet has no payload. Lets continue...")
        return False

    if not Fragmentation["More_Fragments"]:
        if payload[0] == 138:  # corresponds to \x8a (pong)
            return  json.dumps({"src_ip": packet["IP"].src, "dst_ip": packet["IP"].dst,"msg": "pong"})
        elif payload[0] == 137: # corresponds to \x89 (ping)
            return  json.dumps({"src_ip": packet["IP"].src, "dst_ip": packet["IP"].dst,"msg": "ping"})
        elif payload[0] == 129:  # 129 corresponds to \x81 (opcode=text)
            unmasked = []
            if payload[1] & 128 == 128:  # if mask bit is set
                if (payload[1] & 127) == 126: # if payload length is 126, then extended payload header length is 2 bytes
                    
                    mask = [payload[4], payload[5], payload[6], payload[7]]

                    extended_payload_length = int.from_bytes(bytearray(list([payload[2], payload[3]])), byteorder='big')
                    websocket_header_length = 8

                    if extended_payload_length > 1400:  # if payload size exceeds the maximum TCP payload 
                        # This means that we expect more websocket packets!

                        Fragmentation["More_Fragments"] = True
                        Fragmentation["Fragments"].append(payload[websocket_header_length:])
                        Fragmentation["Total_Fragments"] = math.ceil(extended_payload_length/1400)
                        Fragmentation["SrcIP"] = packet.payload.src
                        Fragmentation["SrcPort"] = packet.payload.payload.sport
                        Fragmentation["DstIP"] = packet.payload.dst
                        Fragmentation["DstPort"] = packet.payload.payload.dport
                        Fragmentation["Masked"] = True
                        Fragmentation["Mask"] = mask

                        return False                        

                elif (payload[1] & 127) == 127:  # if payload length is 127, then extended payload header length is 8 bytes
                    mask = [payload[10], payload[11], payload[12], payload[13]]
                    websocket_header_length = 14
                else:  # if payload length is normal and mask is set 
                    mask = [payload[2], payload[3], payload[4], payload[5]]
                    websocket_header_length = 6
                
                unmasked = unmask(payload, mask, websocket_header_length)
                try:
                    unmasked = bytearray.decode(unmasked)
                except UnicodeDecodeError:
                    return False
            else:  # if unmasked
                if (payload[1] & 127) == 126:  # if payload length is 126, then extended payload header length is 2 bytes 
                    websocket_header_length = 4
                elif (payload[1] & 127) == 127:  # if payload length is 127, then extended payload header length is 8 bytes
                    websocket_header_length = 10
                else:
                    websocket_header_length = 2
                unmasked = payload[websocket_header_length:]
                try:
                    unmasked = unmasked.decode()
                except UnicodeDecodeError:
                    return False 
            
            unmasked = json.loads(unmasked)
            return json.dumps({"src_ip": packet["IP"].src, "dst_ip": packet["IP"].dst,"msg": unmasked})

        else: # some other packet
            return False

    # This is to ascertain whether we are now in a fragmented packet (however, the best way to do this is to calculate its expected seq number) 
    elif Fragmentation["SrcIP"] == packet.payload.src and Fragmentation["SrcPort"] == packet.payload.payload.sport and Fragmentation["DstIP"] == packet.payload.dst and Fragmentation["DstPort"] == packet.payload.payload.dport:
        
        Fragmentation["Fragments"].append(payload)

        if len(Fragmentation["Fragments"]) == Fragmentation["Total_Fragments"]:  # Check if we collected all fragmented packets
            Fragmentation["More_Fragments"] = False
            assembled_payload = b''.join(Fragmentation["Fragments"])
            Fragmentation["Fragments"] = []  # reset Fragments list
            if Fragmentation["Masked"]:
                unmasked = unmask(assembled_payload, Fragmentation["Mask"], 0)
            else:
                unmasked = assembled_payload
                
            unmasked = json.loads(unmasked)
            return json.dumps({"src_ip": packet["IP"].src, "dst_ip": packet["IP"].dst,"msg": unmasked})
    else:
        return False


class FileSink(Sink):
    def push(self, msg):
        if msg == False or msg == 'False':
          return 
        else:
            result = msg
            LOGGER.info(msg=result, extra={'timestamp': datetime.now().timestamp()})


if __name__ == "__main__":

    # CONFIGURATION
    config = configparser.ConfigParser()
    config.read('config.ini')
    OPERATION_MODE = config["Settings"]["OperationMode"]

    Path("ocpp-logs").touch()
    Path("pcaps").touch()

    if OPERATION_MODE == "ONLINE":
        source = SniffSource(iface=config["Settings"]["CaptureInterface"], filter="tcp")
        filesink = FileSink()
        source > TransformDrain(analysePacketOCPP) > filesink
        p = PipeEngine()
        p.add(source)
        p.start()
        p.wait_and_stop()

    elif OPERATION_MODE == "OFFLINE":
        PCAP_FILES = config["Settings"]["OfflineFiles"].split(",")

        for pcap in PCAP_FILES:
            packets = PcapReader("./pcaps/" + pcap)
            for packet in packets:
                if packet.haslayer("TCP"):
                    result = analysePacketOCPP(packet)
                    if not result:
                        continue
                    else:
                        LOGGER.info(msg=result, extra={'timestamp': int(packet.time)})

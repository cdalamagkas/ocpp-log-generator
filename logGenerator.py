from scapy.all import *
from datetime import datetime
import logging
from logging.handlers import RotatingFileHandler
import json
import configparser
import math


class TimestampFilter(logging.Filter):
    def filter(self, record):
        if hasattr(record, 'timestamp'):
            record.created = record.timestamp
        return True


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


def unmask(payload, mask):
    unmasked = []
    i = 0
    for byte in payload:
        byte_unmasked = byte ^ mask[ i % 4 ]
        unmasked.append(byte_unmasked)
        i = i+1
    unmasked = bytearray(unmasked)
    return unmasked


# Returns header length (i.e., how many bytes does the header consume) and payload length
def websocket_header_properties(payload):
    mask = None
    if payload[1] & 128 == 128:  # if mask bit is set
        if (payload[1] & 127) == 126: # if payload length is 126, then extended payload header length is 2 bytes
            payload_length = int.from_bytes(bytearray(list([payload[2], payload[3]])), byteorder='big')
            header_length = 8
            mask = [payload[4], payload[5], payload[6], payload[7]]

        elif (payload[1] & 127) == 127:  # if payload length is 127, then extended payload header length is 8 bytes
            payload_length = int.from_bytes(bytearray(list([payload[2], payload[3],  payload[4], payload[5], payload[6], payload[7], payload[8], payload[9]])), byteorder='big')
            header_length = 14
            mask = [payload[10], payload[11], payload[12], payload[13]]

        else:  # if payload length is normal and mask is set
            payload_length = int.from_bytes(bytearray(list([payload[1] & 127])), byteorder='big')
            header_length = 6
            mask = [payload[2], payload[3], payload[4], payload[5]]

    else: # if mask is not set
        if (payload[1] & 127) == 126:  # if payload length is 126, then extended payload header length is 2 bytes 
            payload_length = int.from_bytes(bytearray(list([payload[2], payload[3]])), byteorder='big')
            header_length = 4
        elif (payload[1] & 127) == 127:  # if payload length is 127, then extended payload header length is 8 bytes
            payload_length = int.from_bytes(bytearray(list([payload[2], payload[3],  payload[4], payload[5], payload[6], payload[7], payload[8], payload[9]])), byteorder='big')
            header_length = 10
        else:
            payload_length = int.from_bytes(bytearray(list([payload[1]])), byteorder='big')
            header_length = 2

    return header_length, payload_length, mask


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
            Websocket_Messages = []
            while True:
                unmasked = []
                header_length, payload_length, mask = websocket_header_properties(payload)

                if payload_length > 1400:  # if payload size exceeds the maximum TCP payload 
                    # This means that we expect more websocket packets!
                    Fragmentation["More_Fragments"] = True
                    Fragmentation["Fragments"].append(payload[header_length:])
                    Fragmentation["Total_Fragments"] = math.ceil(payload_length/1400)
                    Fragmentation["SrcIP"] = packet.payload.src
                    Fragmentation["SrcPort"] = packet.payload.payload.sport
                    Fragmentation["DstIP"] = packet.payload.dst
                    Fragmentation["DstPort"] = packet.payload.payload.dport
                    if mask is not None:
                        Fragmentation["Masked"] = True
                        Fragmentation["Mask"] = mask
                    else:
                        Fragmentation["Masked"] = False

                    return False

                if mask is not None:
                    unmasked = unmask(payload[header_length:header_length+payload_length], mask)
                    try:
                        unmasked = bytearray.decode(unmasked)
                    except UnicodeDecodeError:
                        print("Unicode decode error!")
                        return False
                else:  # if unmasked
                    unmasked = payload[header_length:]
                    try:
                        unmasked = unmasked.decode()
                    except UnicodeDecodeError:
                        print("Unicode decode error!")
                        return False 

                unmasked = json.loads(unmasked)
                Websocket_Messages.append(unmasked)
                
                # If there are more websockets to be parsed in the same packet
                if len(payload[header_length+payload_length:]) > 0: 
                    payload = payload[header_length+payload_length:]
                else:
                    return json.dumps({"src_ip": packet["IP"].src, "dst_ip": packet["IP"].dst,"msg": Websocket_Messages})
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
                unmasked = unmask(assembled_payload, Fragmentation["Mask"])
            else:
                unmasked = assembled_payload
                
            unmasked = json.loads(unmasked)
            return json.dumps({"src_ip": packet["IP"].src, "dst_ip": packet["IP"].dst,"msg": [unmasked]})
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

    if not os.path.isdir("output-logs"):
        os.makedirs("output-logs")

    if not os.path.isdir("pcaps"):
        os.makedirs("pcaps")

    # LOGGING CONFIGURATION ###################
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

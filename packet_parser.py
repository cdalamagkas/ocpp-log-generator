from scapy.all import *
from datetime import datetime
import logging
from logging.handlers import RotatingFileHandler
import json
import configparser
import math
from logGenerator import unmask, websocket_header_properties, TimestampFilter


def analysePacketOCPP(packet):
    try:
        payload = packet["IP"]["TCP"].payload.load
    except AttributeError or IndexError:
        #print("Packet has no payload. Lets continue...")
        return False

    if payload[0] == 138:  # corresponds to \x8a (pong)
        return  json.dumps({"src_ip": packet["IP"].src, "dst_ip": packet["IP"].dst,"msg": "pong"})
    elif payload[0] == 137: # corresponds to \x89 (ping)
        return  json.dumps({"src_ip": packet["IP"].src, "dst_ip": packet["IP"].dst,"msg": "ping"})
    elif payload[0] == 129:  # 129 corresponds to \x81 (opcode=text)
        Websocket_Messages = []
        while True:
            unmasked = []
            header_length, payload_length, mask = websocket_header_properties(payload)

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

            # unmasked = json.loads(unmasked)
            Websocket_Messages.append(unmasked)
            
            # If there are more websockets to be parsed in the same packet
            if len(payload[header_length+payload_length:]) > 0: 
                payload = payload[header_length+payload_length:]
            else:
                return json.dumps({"src_ip": packet["IP"].src, "dst_ip": packet["IP"].dst,"msg": Websocket_Messages})
    else: # some other packet
        return False


if __name__ == "__main__":
    packet_id = 81233
    
    # CONFIGURATION
    config = configparser.ConfigParser()
    config.read('config.ini')

    PCAP_FILES = config["Settings"]["OfflineFiles"].split(";")

    # LOGGING CONFIGURATION ###################
    LOG_FILENAME = datetime.now().strftime("%Y%m%d-%H%M%S") + "_OcppPacketParser.json"
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

    for pcap in PCAP_FILES:
        packets = PcapReader("./pcaps/" + pcap)
        counter = 1
        for packet in packets:
            if packet.haslayer("TCP"):
                if counter >= packet_id:
                    result = analysePacketOCPP(packet)
                    if result is not False:
                        LOGGER.info(msg=result, extra={'timestamp': int(packet.time)})
            counter += 1

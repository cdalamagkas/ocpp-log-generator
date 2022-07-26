from scapy.all import *
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, TCP
import uuid
from datetime import datetime
import logging
from logging.handlers import RotatingFileHandler
import time


# Online means that the script listens to the interface to retrieve ocpp packets
ONLINE_MODE = 1
PCAP_FILES = ["pcaps/20220509-cpms-sample.pcap", "pcaps/cpms-1.pcap", "pcaps/cpms-2.pcap", "pcaps/cpms-new-edited.pcap"]
LOG_FILENAME = str(int(datetime.now().timestamp())) + "_ocppLogs.json"

logging.basicConfig(format='%(asctime)s %(message)s', level=logging.INFO, datefmt='%Y-%m-%dT%H:%M:%S')
LOGGER = logging.getLogger("Rotating Log")
handler = RotatingFileHandler(LOG_FILENAME, maxBytes=2000, backupCount=5)
LOGGER.addHandler(handler)


def analysePacketOCPP(packet):
    try:
        payload = packet["IP"]["TCP"].payload.load
    except AttributeError:
        print("Packet has no payload. Lets continue...")
        return False

    if payload[0] == 129 or payload[0] == 137 or payload[0] == 138:  # 129 corresponds to \x81 (opcode=text), 137 to \x89, 138 to \x8a (pong)
        unmasked = []
        if payload[1] & 128 == 128:  # Check if mask bit is set
            if (payload[1] & 127) == 126:
                mask = [payload[4], payload[5], payload[6], payload[7]]
                n = 8
            elif (payload[1] & 127) == 127:
                mask = [payload[4], payload[5], payload[6], payload[7]]
                n = 8
            else:
                mask = [payload[2], payload[3], payload[4], payload[5]]
                n = 6
            
            i = 0
            for byte in payload[n:]:
                byte_unmasked = byte ^ mask[ i % 4 ]
                unmasked.append(byte_unmasked)
                i = i+1

            unmasked = bytearray(unmasked)
            unmasked = bytearray.decode(unmasked)
        else:
            if (payload[1] & 127) == 126:
                n = 4
            elif (payload[1] & 127) == 127:
                n = 4
            else:
                n = 2
            unmasked = payload[n:]
            unmasked = unmasked.decode()
        return unmasked
    else:
        return False


class FileSink(Sink):
    def push(self, msg):
        if msg == False or msg == 'False':
            print("False, skipping...")
        else:
            LOGGER.info(result)


if __name__ == "__main__":

    if ONLINE_MODE:
        source = SniffSource(filter="tcp")
        filesink = FileSink()
        source > TransformDrain(analysePacketOCPP) > filesink
        p = PipeEngine()
        p.add(source)
        p.start()
        p.wait_and_stop()
        
    else:
        for pcap in PCAP_FILES:
            packets = rdpcap(pcap)
            for packet in packets:
                result = analysePacketOCPP(packet)
                if not result:
                    continue
                else:
                    LOGGER.info(result)

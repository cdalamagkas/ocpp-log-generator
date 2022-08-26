from scapy.all import *
from datetime import datetime
import logging
from logging.handlers import RotatingFileHandler


# Online means that the script listens to the interface to retrieve ocpp packets
ONLINE_MODE = True

# PCAP_FILES is needed only if operating in offline mode (i.e., ONLINE_MODE = False)
PCAP_FILES = ["pcaps/20220509-cpms-sample.pcap", "pcaps/cpms-1.pcap", "pcaps/cpms-2.pcap", "pcaps/cpms-new-edited.pcap"]

LOG_FILENAME = datetime.now().strftime("%Y%m%d-%H%M%S") + "_ocppLogs.json"
FORMAT = '%(asctime)s.%(msecs)03d %(message)s'
DATEFMT = '%Y-%m-%dT%H:%M:%S'
formatter = logging.Formatter(fmt=FORMAT, datefmt=DATEFMT)
logging.basicConfig(format=FORMAT, level=logging.INFO, datefmt=DATEFMT)
LOGGER = logging.getLogger("Rotating Log")
handler = RotatingFileHandler(LOG_FILENAME, maxBytes=15728640, backupCount=5)
handler.setFormatter(formatter)
LOGGER.addHandler(handler)


def analysePacketOCPP(packet):
    try:
        payload = packet["IP"]["TCP"].payload.load
    except AttributeError:
        #print("Packet has no payload. Lets continue...")
        return False

    if payload[0] == 138:  # corresponds to \x8a (pong)
        return  {"src_ip": packet["IP"].src, "dst_ip": packet["IP"].dst,"msg": "pong"} 
    elif payload[0] == 137: # corresponds to \x89 (ping)
        return  {"src_ip": packet["IP"].src, "dst_ip": packet["IP"].dst,"msg": "ping"}
    elif payload[0] == 129:  # 129 corresponds to \x81 (opcode=text), 137 to \x89 (ping), 138 to \x8a (pong)
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
        return {"src_ip": packet["IP"].src, "dst_ip": packet["IP"].dst,"msg": unmasked}
    else:
        return False


class FileSink(Sink):
    def push(self, msg):
        if msg == False or msg == 'False':
          return 
          # print("False, skipping...")
        else:
            LOGGER.info("IP_SRC=" + msg["src_ip"] + " " + "IP_DST=" + msg["dst_ip"] + " MSG=" + msg["msg"])


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

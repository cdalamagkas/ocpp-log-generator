import scapy.all as scapy_all
from datetime import datetime
import logging
from logging.handlers import RotatingFileHandler
import json
import configparser
import math
from os import listdir
from os.path import isfile, join
from kafka import KafkaProducer
#from kafka.admin import KafkaAdminClient, NewTopic
#from kafka.errors import KafkaError
import traceback
import sys


class KafkaLoggingHandler(logging.Handler):

    def __init__(self, config):
        logging.Handler.__init__(self)

        if config["KAFKA_SECURITY"] == "SASL_PLAINTEXT":
            self.producer = KafkaProducer(
                bootstrap_servers='[{0}:{1}]'.format(config["KAFKA_HOST"], config["KAFKA_PORT"]),
                security_protocol='SASL_PLAINTEXT',
                sasl_mechanism='PLAIN',
                sasl_plain_username=config["KAFKA_SASL_USERNAME"],
                sasl_plain_password=config["KAFKA_SASL_PASSWORD"]
            )
        elif config["KAFKA_SECURITY"] == "SSL":
            self.producer = KafkaProducer(
                bootstrap_servers='[{0}:{1}]'.format(config["KAFKA_HOST"], config["KAFKA_PORT"]),
                security_protocol='SSL',
                ssl_check_hostname=False,
                ssl_cafile=config["KAFKA_CA"],
                ssl_certfile=config["KAFKA_CERT"],
                ssl_keyfile=config["KAFKA_KEY"],
                ssl_password=config["KAFKA_PASSWORD"]
            )
        elif config["KAFKA_SECURITY"] == "DISABLED" :
            self.producer = KafkaProducer(bootstrap_servers='[{0}:{1}]'.format(config["KAFKA_HOST"], config["KAFKA_PORT"]))

        self.topic = config["KAFKA_TOPIC"]

    def emit(self, record):
        #drop kafka logging to avoid infinite recursion
        if record.name == 'kafka':
            return
        try:
            #use default formatting
            #msg = self.format(record)
            #produce message
            self.producer.send(self.topic, record.getMessage().encode('utf-8'))
            self.producer.flush()
        except:            
            ei = sys.exc_info()
            traceback.print_exception(ei[0], ei[1], ei[2], None, sys.stderr)
            del ei

    def close(self):
        self.producer.close()
        logging.Handler.close(self)


class TimestampFilter(logging.Filter):
    def filter(self, record):
        if hasattr(record, 'timestamp'):
            record.created = record.timestamp  # type: ignore
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

    if len(payload) == 0:
        return

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
                    packet.show()
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

                try:
                    unmasked = json.loads(unmasked)
                    Websocket_Messages.append(unmasked)
                except json.decoder.JSONDecodeError:
                    return False

                # If there are more websockets to be parsed in the same packet
                if len(payload[header_length+payload_length:]) > 0: 
                    payload = payload[header_length+payload_length:]
                else:
                    return json.dumps({"src_ip": packet["IP"].src, "dst_ip": packet["IP"].dst,"msg": Websocket_Messages})
        else: # some other packet
            return False

    # This is to ascertain whether we are now in a fragmented packet (however, the best way to do this is to calculate its expected seq number) 
    elif Fragmentation["SrcIP"] == packet["IP"].src and Fragmentation["SrcPort"] == packet["IP"]["TCP"].sport and Fragmentation["DstIP"] == packet["IP"].dst and Fragmentation["DstPort"] == packet["IP"]["TCP"].dport:
        
        Fragmentation["Fragments"].append(payload)

        if len(Fragmentation["Fragments"]) == Fragmentation["Total_Fragments"]:  # Check if we collected all fragmented packets
            Fragmentation["More_Fragments"] = False
            assembled_payload = b''.join(Fragmentation["Fragments"])
            Fragmentation["Fragments"] = []  # reset Fragments list
            if Fragmentation["Masked"]:
                unmasked = unmask(assembled_payload, Fragmentation["Mask"])
            else:
                unmasked = assembled_payload

            try:    
                unmasked = json.loads(unmasked)
            except:
                print("Decoding error on fragmented packet")
                print(unmasked)
                return False

            return json.dumps({"src_ip": packet["IP"].src, "dst_ip": packet["IP"].dst,"msg": [unmasked]})
    else:
        return False


class FileSink(scapy_all.Sink):
    def push(self, msg):
        if msg == False or msg == 'False':
          return 
        else:
            result = msg
            LOGGER.info(msg=result, extra={'timestamp': datetime.now().timestamp()})


if __name__ == "__main__":

    ## Load configuration file
    config = None
    with open('config.json') as f:
        config = json.load(f)

    if not scapy_all.os.path.isdir("output-logs"):
        scapy_all.os.makedirs("output-logs")

    if not scapy_all.os.path.isdir("pcaps"):
        scapy_all.os.makedirs("pcaps")

    # LOGGING CONFIGURATION ###################
    FORMAT = '%(asctime)s.%(msecs)03dZ %(message)s'
    DATEFMT = '%Y-%m-%dT%H:%M:%S'
    formatter = logging.Formatter(fmt=FORMAT, datefmt=DATEFMT)
    logging.basicConfig(format=FORMAT, level=logging.INFO, datefmt=DATEFMT)
    filter = TimestampFilter()
    
    
    if config["General"]["OPERATION_MODE"] == "ONLINE":

        LOGGER = logging.getLogger("Online Logger")
        LOGGER.addFilter(filter)

        LOG_FILENAME = datetime.now().strftime("%Y%m%d-%H%M%S") + "_ocppLogs.json"
        handler = RotatingFileHandler("./output-logs/" + LOG_FILENAME, maxBytes=15728640, backupCount=5)
        handler.setFormatter(formatter)
        LOGGER.addHandler(handler)

        if config["General"]["OUTPUT_KAFKA"]:
            handler = KafkaLoggingHandler(config=config["Kafka"])
            handler.setFormatter(formatter)
            LOGGER.addHandler(handler)

        source = scapy_all.SniffSource(iface=config["General"]["ONLINE_CAPTURE_INTERFACE"], filter="tcp")
        filesink = FileSink()
        source > scapy_all.TransformDrain(analysePacketOCPP) > filesink
        p = scapy_all.PipeEngine()
        p.add(source)
        p.start()
        p.wait_and_stop()

    elif config["General"]["OPERATION_MODE"] == "OFFLINE":
        PCAP_FILES = config["General"]["OFFLINE_PCAP_FILES"]
        if "*" in PCAP_FILES:
            PCAP_FILES = [f for f in listdir("./pcaps") if isfile(join("./pcaps", f))]

        for pcap in PCAP_FILES:
            LOGGER = logging.getLogger(pcap)
            LOGGER.addFilter(filter)
            LOG_FILENAME = datetime.now().strftime("%Y%m%d-%H%M%S") + "_ocppLogs_" + pcap.split(".")[0] + ".json"
            handler = RotatingFileHandler("./output-logs/" + LOG_FILENAME, maxBytes=15728640, backupCount=5)
            handler.setFormatter(formatter)
            LOGGER.addHandler(handler)

            packets = scapy_all.PcapReader("./pcaps/" + pcap)
            for packet in packets:
                if packet.haslayer("TCP"):
                    result = analysePacketOCPP(packet)
                    if not result:
                        continue
                    else:
                        LOGGER.info(msg=result, extra={'timestamp': int(packet.time)})

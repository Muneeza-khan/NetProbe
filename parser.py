# Simple parser functions to filter or parse packets if needed

def filter_by_protocol(packet, protocol):
    return packet["protocol"] == protocol

def filter_by_ip(packet, ip):
    return packet["src_ip"] == ip or packet["dst_ip"] == ip

def filter_by_port(packet, port):
    return packet["src_port"] == port or packet["dst_port"] == port
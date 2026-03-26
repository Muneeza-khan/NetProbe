def detect_suspicious(packet):

    if packet["size"] > 1500:
        return "Large Packet"

    if packet["protocol"] == "TCP" and packet["dst_port"] == 22:
        return "SSH Traffic"

    return None
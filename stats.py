class PacketStats:

    def __init__(self):
        self.total = 0
        self.tcp = 0
        self.udp = 0
        self.icmp = 0
        self.other = 0
        self.total_bytes = 0
        self.alert_count = 0

    def update(self, packet):
        self.total += 1
        self.total_bytes += packet.get("size", 0)
        proto = packet.get("protocol", "OTHER")
        if proto == "TCP":
            self.tcp += 1
        elif proto == "UDP":
            self.udp += 1
        elif proto == "ICMP":
            self.icmp += 1
        else:
            self.other += 1
        if packet.get("alert"):
            self.alert_count += 1

    def summary(self):
        return {
            "Total Packets": self.total,
            "Total Bytes": self.total_bytes,
            "TCP": self.tcp,
            "UDP": self.udp,
            "ICMP": self.icmp,
            "Other": self.other,
            "Alerts": self.alert_count,
        }

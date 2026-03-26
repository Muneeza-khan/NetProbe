from scapy.all import sniff, IP, TCP, UDP, ICMP
from core.detector import detect_suspicious
import threading

class NetProbeSniffer:

    def __init__(self, interface=None):
        self.interface = interface
        self.capture_running = False
        self.packets = []

    def _handle_packet(self, pkt, callback):
        if IP not in pkt:
            return

        packet_info = {
            "time": pkt.time,
            "src_ip": pkt[IP].src,
            "dst_ip": pkt[IP].dst,
            "size": len(pkt)
        }

        if TCP in pkt:
            packet_info["protocol"] = "TCP"
            packet_info["src_port"] = pkt[TCP].sport
            packet_info["dst_port"] = pkt[TCP].dport
        elif UDP in pkt:
            packet_info["protocol"] = "UDP"
            packet_info["src_port"] = pkt[UDP].sport
            packet_info["dst_port"] = pkt[UDP].dport
        elif ICMP in pkt:
            packet_info["protocol"] = "ICMP"
            packet_info["src_port"] = "-"
            packet_info["dst_port"] = "-"
        else:
            packet_info["protocol"] = "OTHER"
            packet_info["src_port"] = "-"
            packet_info["dst_port"] = "-"

        packet_info["alert"] = detect_suspicious(packet_info)

        self.packets.append(packet_info)

        if callback:
            callback(packet_info)

    def _sniff_thread(self, callback):
        sniff(iface=self.interface, prn=lambda pkt: self._handle_packet(pkt, callback), store=False)

    def start(self, callback=None):
        self.capture_running = True
        t = threading.Thread(target=self._sniff_thread, args=(callback,))
        t.start()

    def stop(self):
        self.capture_running = False
        # Note: scapy sniff doesn't stop gracefully, we use thread + KeyboardInterrupt in CLI
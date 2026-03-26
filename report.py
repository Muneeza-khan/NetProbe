# core/report.py
from fpdf import FPDF
import os

def generate_pdf_report(sniffer, stats):
    packets = sniffer.packets  # <-- CLI se pass hua instance
    if not packets:
        print("No packets captured!")
        return

    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", "B", 14)
    pdf.cell(0, 10, "NetProbe Packet Capture Report", ln=True, align="C")
    pdf.ln(10)

    pdf.set_font("Arial", size=12)
    for i, pkt in enumerate(packets, 1):
        pdf.multi_cell(
            0, 8,
            f"{i}. Time:{pkt['time']}, Src:{pkt['src_ip']}:{pkt.get('src_port', '-')}, "
            f"Dst:{pkt['dst_ip']}:{pkt.get('dst_port', '-')}, Proto:{pkt['protocol']}, "
            f"Size:{pkt['size']}, Alert:{pkt['alert']}"
        )
        pdf.ln(1)

    if not os.path.exists("logs"):
        os.makedirs("logs")

    pdf.output("logs/packet_report.pdf")
    print("PDF report generated: logs/packet_report.pdf")
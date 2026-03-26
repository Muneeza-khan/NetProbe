import os
import sys
import threading
import termios
import tty
from colorama import Fore, Style, init
from tabulate import tabulate
from core.sniffer import NetProbeSniffer
from core.stats import PacketStats
from core.report import generate_pdf_report

init(autoreset=True)

CTRL_Q = "\x11"


def start_cli_sniffer():
    cli = NetProbeCLI()
    cli.start()


class NetProbeCLI:

    def __init__(self, interface=None):
        self.interface = interface
        self.stats = PacketStats()
        self.sniffer = NetProbeSniffer(interface)
        self._kb_thread = None
        self._kb_stop = threading.Event()

    def banner(self):
        os.system("cls" if os.name == "nt" else "clear")
        print(Fore.CYAN + r"""
███╗   ██╗███████╗████████╗██████╗ ██████╗  ██████╗ ██████╗ ███████╗
████╗  ██║██╔════╝╚══██╔══╝██╔══██╗██╔══██╗██╔═══██╗██╔══██╗██╔════╝
██╔██╗ ██║█████╗     ██║   ██████╔╝██████╔╝██║   ██║██████╔╝█████╗
██║╚██╗██║██╔══╝     ██║   ██╔═══╝ ██╔══██╗██║   ██║██╔══██╗██╔══╝
██║ ╚████║███████╗   ██║   ██║     ██║  ██║╚██████╔╝██████╔╝███████╗
╚═╝  ╚═══╝╚══════╝   ╚═╝   ╚═╝     ╚═╝  ╚═╝ ╚═════╝ ╚═════╝ ╚══════╝
        """)
        print(Fore.YELLOW + " NetProbe - Network Packet Sniffer")
        print(Fore.YELLOW + " Ethical Network Monitoring Tool\n")
        print(Fore.GREEN + " Commands: start | stop | report | exit")
        print(Fore.GREEN + " During capture: press Ctrl+Q to stop instantly.\n")

    def display_packet(self, packet):
        self.stats.update(packet)
        proto = packet.get("protocol", "?")
        color = Fore.WHITE
        if proto == "TCP":
            color = Fore.GREEN
        elif proto == "UDP":
            color = Fore.YELLOW
        elif proto == "ICMP":
            color = Fore.MAGENTA

        alert = packet.get("alert")
        if alert:
            print(Fore.RED + f"\n  [ALERT] {alert}")

        row = [
            packet.get("time", "-"),
            packet.get("src_ip", "-"),
            packet.get("dst_ip", "-"),
            proto,
            packet.get("src_port", "-"),
            packet.get("dst_port", "-"),
            packet.get("size", 0),
        ]
        print(
            color
            + tabulate(
                [row],
                headers=["Time", "Source IP", "Destination IP", "Proto", "SrcPort", "DstPort", "Bytes"],
                tablefmt="plain",
            )
        )

    def _keyboard_listener(self):
        """
        Runs in a background thread while capture is active.
        Reads raw keypresses — pressing Ctrl+Q (0x11) stops the capture.
        Falls back gracefully if the terminal is not a real TTY.
        """
        if not sys.stdin.isatty():
            return

        fd = sys.stdin.fileno()
        old_settings = termios.tcgetattr(fd)
        try:
            tty.setraw(fd)
            while not self._kb_stop.is_set():
                ch = os.read(fd, 1).decode("utf-8", errors="ignore")
                if ch == CTRL_Q or ch == "\x03":
                    print(Fore.RED + "\n\n[Ctrl+Q] Stopping capture...")
                    self.sniffer.stop()
                    break
        except Exception:
            pass
        finally:
            try:
                termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)
            except Exception:
                pass

    def _start_keyboard_listener(self):
        self._kb_stop.clear()
        self._kb_thread = threading.Thread(
            target=self._keyboard_listener,
            daemon=True,
        )
        self._kb_thread.start()

    def _stop_keyboard_listener(self):
        self._kb_stop.set()

    def _do_start(self):
        if self.sniffer.is_running():
            print(Fore.YELLOW + "Capture is already running.")
            return

        self.sniffer = NetProbeSniffer(self.interface)
        self.stats = PacketStats()
        print(Fore.GREEN + "\nStarting packet capture...")
        print(Fore.CYAN + "  Press Ctrl+Q at any time to stop, or type 'stop' and press Enter.\n")
        self.sniffer.start(callback=self.display_packet)
        self._start_keyboard_listener()

    def _do_stop(self):
        if not self.sniffer.is_running():
            print(Fore.YELLOW + "No active capture to stop.")
            return
        self._stop_keyboard_listener()
        self.sniffer.stop()
        self._print_summary()

    def _do_report(self):
        if self.sniffer.is_running():
            print(Fore.YELLOW + "Capture is still running. Stop it first with 'stop' or Ctrl+Q.")
            return
        if not self.sniffer.packets:
            print(Fore.YELLOW + "No packets captured yet. Run 'start' first.")
            return
        print(Fore.CYAN + "\nGenerating PDF report...")
        print("PDF generation started...")
        generate_pdf_report(self.sniffer, self.stats)
    

    def _print_summary(self):
        summary = self.stats.summary()
        duration = self.sniffer.capture_duration()
        mins = int(duration // 60)
        secs = int(duration % 60)
        print(Fore.CYAN + "\n--- Capture Summary ---")
        print(Fore.WHITE + f"  Duration    : {mins}m {secs}s")
        for k, v in summary.items():
            print(Fore.WHITE + f"  {k:<16}: {v}")
        print(Fore.CYAN + "-----------------------\n")
        print(Fore.GREEN + "Type 'report' to generate a PDF report.")

    def start(self):
        self.banner()
        while True:
            try:
                cmd = input(Fore.CYAN + "\nNetProbe CLI > ").strip().lower()
            except (EOFError, KeyboardInterrupt):
                if self.sniffer.is_running():
                    self._do_stop()
                print(Fore.YELLOW + "\nExiting NetProbe CLI.")
                break

            if cmd == "start":
                self._do_start()
            elif cmd == "stop":
                self._do_stop()
            elif cmd == "report":
                self._do_report()
            elif cmd == "exit":
                if self.sniffer.is_running():
                    self._do_stop()
                print(Fore.YELLOW + "Exiting NetProbe CLI.")
                break
            elif cmd == "":
                continue
            else:
                print(Fore.RED + f"  Unknown command: '{cmd}'")
                print(Fore.WHITE + "  Available commands: start | stop | report | exit")

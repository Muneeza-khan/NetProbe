# Main.py
import argparse
from cli.cli_tools import start_cli_sniffer

def main():
    parser = argparse.ArgumentParser(description="NetProbe Network Sniffer CLI")

    parser.add_argument(
        "--cli",
        action="store_true",
        help="Run NetProbe in CLI mode"
    )

    args = parser.parse_args()

    if args.cli:
        start_cli_sniffer()
    else:
        print("\nGUI removed in this version.")
        print("Run the tool in CLI mode with:\n")
        print("    python Main.py --cli\n")
        print("Available commands once CLI starts: start | stop | report | exit")

if __name__ == "__main__":
    main()
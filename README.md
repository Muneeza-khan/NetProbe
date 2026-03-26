#NetProbe
NetProbe is a lightweight Python network packet sniffer and analyzer with a CLI interface. It captures network packets and analyzes statistics.
#Features
Capture network packets in real-time
Analyze packet statistics
Command-line interface (CLI) only
#Installation
git clone <https://github.com/Muneeza-khan/NetProbe>
cd NetProbe
python -m venv venv
source venv/bin/activate   # Linux/macOS
# or for Windows
venv\Scripts\activate
pip install -r requirements.txt
#Usage
Start the CLI sniffer:
python -c "from cli.cli_tools import start_cli_sniffer; start_cli_sniffer()" 
Note: To stop capturing, simply close the CLI/browser window or press Ctrl+C to return to the terminal. PDF reports are generated automatically after capture ends.
#Author
© 2026 Muneeza Khan – NetProbe

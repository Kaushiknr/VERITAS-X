"""Desktop Executable Launcher for VERITAS-X Digital Forensics Platform."""
import os
import sys
import time
import socket
import webbrowser
import threading
from pathlib import Path

# Add project root to sys.path
BASE_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(BASE_DIR))

import uvicorn
from api.main import app

def is_port_open(host: str, port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(0.5)
        return s.connect_ex((host, port)) == 0

def open_browser(url: str):
    time.sleep(1.2)
    for _ in range(20):
        if is_port_open("127.0.0.1", 8000):
            webbrowser.open(url)
            break
        time.sleep(0.5)

def main():
    host = "127.0.0.1"
    port = 8000
    url = f"http://{host}:{port}/"

    print("=" * 64)
    print("  VERITAS-X : Digital Forensics & Evidence Intelligence Platform")
    print("  Trust the evidence. Verify the conclusion.")
    print("=" * 64)
    print(f"  [+] Initializing local immutable vault...")
    print(f"  [+] Starting investigation engine at {url}")
    print(f"  [+] Opening investigation console in your browser...")
    print("=" * 64)

    # Launch browser in separate thread
    threading.Thread(target=open_browser, args=(url,), daemon=True).start()

    # Run uvicorn server
    uvicorn.run(app, host=host, port=port, log_level="warning")

if __name__ == "__main__":
    main()

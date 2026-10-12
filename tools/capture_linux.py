"""Explicitly invoked read-only capture. Never called by an importer or the app."""
import argparse
import datetime as dt
import json
from pathlib import Path
import socket
import subprocess


def capture(args):
    result = subprocess.run(["ip", "-j", *args], check=True, capture_output=True, timeout=10, text=True)
    if len(result.stdout.encode()) > 8 * 1024 * 1024:
        raise ValueError("Captured output exceeds the supported limit.")
    data = json.loads(result.stdout)
    if not isinstance(data, list):
        raise ValueError("Expected iproute2 JSON array.")
    return data


def main():
    parser = argparse.ArgumentParser(description="Read local Linux interface, route and neighbor tables. Does not scan or change devices.")
    parser.add_argument("output", type=Path, help="New output file in your protected evidence store")
    args = parser.parse_args()
    version = subprocess.run(["ip", "-V"], capture_output=True, text=True, check=True, timeout=10).stdout.strip()
    bundle = {"format":"linux-ip/1", "device":socket.gethostname(), "version":version,
              "collected_at":dt.datetime.now(dt.timezone.utc).isoformat(), "addresses":capture(["address", "show"]),
              "routes":capture(["route", "show", "table", "all"]), "neighbors":capture(["neigh", "show"])}
    # Exclusive creation preserves pre-existing evidence.
    with args.output.open("x", encoding="utf-8") as file:
        json.dump(bundle, file, indent=2)
    print("Read-only capture saved. Review sensitivity before importing.")


if __name__ == "__main__":
    main()

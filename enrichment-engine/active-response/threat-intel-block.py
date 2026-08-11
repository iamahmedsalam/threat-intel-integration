#!/usr/bin/env python3
"""
Wazuh Active Response script - threat intel auto-block.

NOTE: During Phase D testing, Wazuh's execd Active Response dispatch
was found to be unreliable in this deployment (intermittent silent
failures - matches known upstream issue wazuh/wazuh#9370, where AR
timeout/dispatch handling regressed in the 4.2 rework). This script
is kept as the "official" Wazuh AR integration and works correctly
when invoked manually or when execd dispatch succeeds, but the
enrichment engine no longer depends on it for containment - see
apply_direct_block() in src/main.py for the reliable, in-process
alternative actually used in production.

This script is retained in the repo for documentation purposes and
because it demonstrates the standard Wazuh custom Active Response
pattern (JSON payload via stdin, add/delete command handling).
"""
import sys
import json
import subprocess
import datetime
import select

LOG_FILE = "/var/ossec/logs/active-responses.log"
DEBUG_FILE = "/var/ossec/logs/threat-intel-debug.log"


def write_log(message):
    timestamp = datetime.datetime.now().strftime("%Y/%m/%d %H:%M:%S")
    with open(LOG_FILE, "a") as f:
        f.write(f"{timestamp} {message}\n")


def write_debug(message):
    timestamp = datetime.datetime.now().strftime("%Y/%m/%d %H:%M:%S")
    with open(DEBUG_FILE, "a") as f:
        f.write(f"{timestamp} {message}\n")


def read_stdin_with_timeout(timeout_seconds=5):
    ready, _, _ = select.select([sys.stdin], [], [], timeout_seconds)
    if ready:
        return sys.stdin.read()
    else:
        return None


def main():
    write_debug("SCRIPT STARTED")

    input_str = read_stdin_with_timeout(5)

    if input_str is None:
        write_debug("STDIN READ TIMED OUT after 5 seconds")
        return

    write_debug(f"RAW STDIN RECEIVED: {repr(input_str)}")

    try:
        data = json.loads(input_str)
        write_debug(f"JSON PARSED OK: {data}")
    except Exception as e:
        write_debug(f"JSON PARSE FAILED: {e}")
        return

    command = data.get("command")
    write_debug(f"COMMAND: {command}")

    alert = data.get("parameters", {}).get("alert", {})
    ip = alert.get("data", {}).get("enrichment_ip")
    write_debug(f"EXTRACTED IP: {ip}")

    if not ip:
        write_log("threat-intel-block: no enrichment_ip found, skipping")
        write_debug("NO IP FOUND, EXITING")
        return

    if command == "add":
        try:
            result = subprocess.run(
                ["iptables", "-I", "INPUT", "-s", ip, "-j", "DROP"],
                capture_output=True, text=True
            )
            write_debug(f"IPTABLES RESULT: returncode={result.returncode}, stdout={result.stdout}, stderr={result.stderr}")
            write_log(f"threat-intel-block: BLOCKED {ip}")
        except Exception as e:
            write_debug(f"IPTABLES EXCEPTION: {e}")
    elif command == "delete":
        subprocess.run(["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"])
        write_log(f"threat-intel-block: UNBLOCKED {ip} (timeout expired)")


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        write_debug(f"UNCAUGHT EXCEPTION IN MAIN: {e}")

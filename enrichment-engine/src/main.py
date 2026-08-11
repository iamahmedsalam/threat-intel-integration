import json
import os
import time
import subprocess
import logging
from src.config import load_config
from src.logger import setup_logger
from src.enrichment import EnrichmentEngine

logger = logging.getLogger("enrichment")

INTEL_ALERT_FILE = "/home/wazuhuser/enrichment-engine/logs/enrichment_alerts.json"


def extract_ip(alert):
    try:
        srcip = alert.get("data", {}).get("srcip", "")
        if srcip:
            return srcip

        win_data = alert.get("data", {}).get("win", {}).get("eventdata", {})
        srcip = win_data.get("sourceIp", "")
        if srcip:
            return srcip

        return None
    except Exception:
        return None


def write_intel_alert(result):
    try:
        alert_line = {
            "enrichment_ip": result["source_ip"],
            "verdict": result["enrichment"]["verdict"],
            "wazuh_rule_id": str(result["rule_id"]),
            "wazuh_rule_description": result["rule_description"],
            "agent": result["agent"],
            "abuse_score": result["enrichment"]["summary"]["abuse_score"],
            "otx_pulses": result["enrichment"]["summary"]["otx_pulses"],
            "misp_matched": result["enrichment"]["summary"]["misp_matched"],
            "sources_responding": result["enrichment"]["sources_responding"]
        }

        with open(INTEL_ALERT_FILE, "a") as f:
            f.write(json.dumps(alert_line) + "\n")

    except Exception as e:
        logger.error(f"Failed to write intel alert: {e}")


def apply_direct_block(ip):
    """
    Direct-invocation blocking architecture.

    Discovered during Phase D testing: Wazuh's execd Active Response
    dispatch is unreliable in this deployment (matches known upstream
    issue wazuh/wazuh#9370 - AR timeout/dispatch handling regressed in
    the 4.2 rework). Rather than depend on execd, the enrichment engine
    applies the firewall block directly and in-process the moment a
    BLOCK verdict is calculated. Wazuh Rule 100016 still fires and is
    visible in the dashboard for analyst awareness - this function is
    purely the containment action, decoupled from Wazuh's own AR
    dispatch reliability.
    """
    try:
        check = subprocess.run(
            ["sudo", "/sbin/iptables", "-C", "INPUT", "-s", ip, "-j", "DROP"],
            capture_output=True
        )
        if check.returncode == 0:
            logger.info(f"Direct block: {ip} already blocked, skipping")
            return

        result = subprocess.run(
            ["sudo", "/sbin/iptables", "-I", "INPUT", "-s", ip, "-j", "DROP"],
            capture_output=True, text=True
        )
        if result.returncode == 0:
            logger.warning(f"Direct block: BLOCKED {ip} via enrichment engine (bypassing Wazuh AR)")
            with open("/var/ossec/logs/active-responses.log", "a") as f:
                timestamp = time.strftime("%Y/%m/%d %H:%M:%S")
                f.write(f"{timestamp} enrichment-engine-direct: BLOCKED {ip}\n")
        else:
            logger.error(f"Direct block failed for {ip}: {result.stderr}")
    except Exception as e:
        logger.error(f"Direct block exception for {ip}: {e}")


def process_alert(alert, engine):
    rule_id = alert.get("rule", {}).get("id", "unknown")
    rule_level = alert.get("rule", {}).get("level", 0)
    rule_desc = alert.get("rule", {}).get("description", "")
    agent_name = alert.get("agent", {}).get("name", "unknown")
    timestamp = alert.get("timestamp", "")

    ip = extract_ip(alert)

    if not ip:
        return None

    if ip.startswith("192.168.") or ip.startswith("10.") or ip == "127.0.0.1":
        logger.info(f"Skipping private IP: {ip} (rule {rule_id})")
        return None

    enrichment = engine.enrich_ip(ip)

    result = {
        "timestamp": timestamp,
        "rule_id": rule_id,
        "rule_level": rule_level,
        "rule_description": rule_desc,
        "agent": agent_name,
        "source_ip": ip,
        "enrichment": enrichment
    }

    verdict = enrichment["verdict"]

    if verdict == "BLOCK":
        logger.warning(f"BLOCK: {ip} (rule {rule_id}, agent {agent_name}) — "
                        f"abuse={enrichment['summary']['abuse_score']}, "
                        f"otx={enrichment['summary']['otx_pulses']}, "
                        f"misp={enrichment['summary']['misp_matched']}")
    elif verdict in ["LIKELY_MALICIOUS", "REVIEW", "SUSPICIOUS"]:
        logger.warning(f"{verdict}: {ip} (rule {rule_id}, agent {agent_name})")
    else:
        logger.info(f"CLEAN: {ip} (rule {rule_id}, agent {agent_name})")

    write_intel_alert(result)

    if verdict == "BLOCK":
        apply_direct_block(ip)

    return result


def watch_alerts(config, engine):
    alert_file = config["alerts"]["watch_file"]
    logger.info(f"Watching: {alert_file}")

    try:
        file = open(alert_file, "r")
        file.seek(0, 2)
        logger.info("Moved to end of file, waiting for new alerts...")

        while True:
            line = file.readline()

            if not line:
                time.sleep(1)
                continue

            line = line.strip()
            if not line:
                continue

            try:
                alert = json.loads(line)
            except json.JSONDecodeError:
                continue

            result = process_alert(alert, engine)

            if result:
                verdict = result["enrichment"]["verdict"]
                print(f"[{verdict}] Rule {result['rule_id']} — "
                      f"{result['source_ip']} — "
                      f"Abuse: {result['enrichment']['summary']['abuse_score']}/100")

    except KeyboardInterrupt:
        logger.info("Enrichment engine stopped by user")
        print("\nEngine stopped.")
    except Exception as e:
        logger.error(f"Watch error: {e}")


def main():
    logger = setup_logger()
    config = load_config()

    logger.info("=== Enrichment Engine Starting ===")
    print("Enrichment Engine starting...")
    print("Initializing threat intel sources...")

    engine = EnrichmentEngine(config)

    print("Engine ready. Watching for new alerts...")
    print("Press Ctrl+C to stop.\n")

    watch_alerts(config, engine)

    logger.info("=== Enrichment Engine Stopped ===")


if __name__ == "__main__":
    main()

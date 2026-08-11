import requests
import logging

logger = logging.getLogger("enrichment")


class OTXClient:

    def __init__(self, api_key, url):
        self.api_key = api_key
        self.url = url
        self.headers = {
            "X-OTX-API-KEY": self.api_key
        }

    def check_ip(self, ip):
        try:
            endpoint = f"{self.url}/indicators/IPv4/{ip}/general"

            response = requests.get(endpoint, headers=self.headers)

            if response.status_code != 200:
                logger.error(f"OTX returned {response.status_code} for {ip}")
                return None

            data = response.json()

            pulse_count = data.get("pulse_info", {}).get("count", 0)

            pulses = []
            for pulse in data.get("pulse_info", {}).get("pulses", [])[:5]:
                pulses.append(pulse.get("name", "Unknown"))

            result = {
                "source": "otx",
                "ip": ip,
                "pulse_count": pulse_count,
                "pulse_names": pulses,
                "country": data.get("country_name", "Unknown"),
                "asn": data.get("asn", "Unknown")
            }

            logger.info(f"OTX: {ip} pulses={pulse_count}")
            return result

        except Exception as e:
            logger.error(f"OTX error for {ip}: {e}")
            return None

    def check_hash(self, file_hash):
        try:
            endpoint = f"{self.url}/indicators/file/{file_hash}/general"

            response = requests.get(endpoint, headers=self.headers)

            if response.status_code != 200:
                logger.error(f"OTX returned {response.status_code} for hash {file_hash}")
                return None

            data = response.json()

            pulse_count = data.get("pulse_info", {}).get("count", 0)

            pulses = []
            for pulse in data.get("pulse_info", {}).get("pulses", [])[:5]:
                pulses.append(pulse.get("name", "Unknown"))

            result = {
                "source": "otx",
                "hash": file_hash,
                "pulse_count": pulse_count,
                "pulse_names": pulses
            }

            logger.info(f"OTX hash check: {file_hash} pulses={pulse_count}")
            return result

        except Exception as e:
            logger.error(f"OTX hash check error for {file_hash}: {e}")
            return None

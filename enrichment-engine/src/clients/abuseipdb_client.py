import requests
import logging

logger = logging.getLogger("enrichment")


class AbuseIPDBClient:

    def __init__(self, api_key, url):
        self.api_key = api_key
        self.url = url
        self.headers = {
            "Key": self.api_key,
            "Accept": "application/json"
        }

    def check_ip(self, ip):
        try:
            response = requests.get(
                self.url,
                headers=self.headers,
                params={"ipAddress": ip, "maxAgeInDays": 90}
            )

            if response.status_code != 200:
                logger.error(f"AbuseIPDB returned {response.status_code} for {ip}")
                return None

            data = response.json()["data"]

            result = {
                "source": "abuseipdb",
                "ip": ip,
                "score": data["abuseConfidenceScore"],
                "country": data["countryCode"],
                "isp": data["isp"],
                "reports": data["totalReports"],
                "is_tor": data["isTor"]
            }

            logger.info(f"AbuseIPDB: {ip} score={result['score']}, reports={result['reports']}")
            return result

        except Exception as e:
            logger.error(f"AbuseIPDB error for {ip}: {e}")
            return None

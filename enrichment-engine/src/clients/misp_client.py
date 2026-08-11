from pymisp import PyMISP
import logging
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logger = logging.getLogger("enrichment")


class MISPClient:

    def __init__(self, api_key, url, verify_ssl=False):
        try:
            self.misp = PyMISP(url, api_key, ssl=verify_ssl)
            logger.info("MISP connection established")
        except Exception as e:
            logger.error(f"MISP connection failed: {e}")
            self.misp = None

    def check_ip(self, ip):
        if self.misp is None:
            logger.error("MISP not connected, cannot check IP")
            return None

        try:
            result = self.misp.search(
                controller="attributes",
                value=ip,
                type_attribute="ip-src",
                pythonify=False
            )

            attributes = result.get("Attribute", [])

            if not attributes:
                result2 = self.misp.search(
                    controller="attributes",
                    value=ip,
                    type_attribute="ip-dst",
                    pythonify=False
                )
                attributes = result2.get("Attribute", [])

            match_count = len(attributes)

            events = []
            for attr in attributes[:5]:
                event_id = attr.get("event_id", "Unknown")
                events.append(event_id)

            result = {
                "source": "misp",
                "ip": ip,
                "match_count": match_count,
                "event_ids": events,
                "matched": match_count > 0
            }

            logger.info(f"MISP: {ip} matches={match_count}")
            return result

        except Exception as e:
            logger.error(f"MISP error for {ip}: {e}")
            return None

    def check_hash(self, file_hash):
        if self.misp is None:
            logger.error("MISP not connected, cannot check hash")
            return None

        hash_types = ["md5", "sha1", "sha256"]

        try:
            for hash_type in hash_types:
                result = self.misp.search(
                    controller="attributes",
                    value=file_hash,
                    type_attribute=hash_type,
                    pythonify=False
                )

                attributes = result.get("Attribute", [])

                if attributes:
                    match_count = len(attributes)
                    events = [a.get("event_id", "Unknown") for a in attributes[:5]]

                    result = {
                        "source": "misp",
                        "hash": file_hash,
                        "hash_type": hash_type,
                        "match_count": match_count,
                        "event_ids": events,
                        "matched": True
                    }
                    logger.info(f"MISP hash check: {file_hash} matched as {hash_type}, {match_count} hits")
                    return result

            result = {
                "source": "misp",
                "hash": file_hash,
                "hash_type": None,
                "match_count": 0,
                "event_ids": [],
                "matched": False
            }
            logger.info(f"MISP hash check: {file_hash} no matches")
            return result

        except Exception as e:
            logger.error(f"MISP hash check error for {file_hash}: {e}")
            return None

import logging
from src.clients.abuseipdb_client import AbuseIPDBClient
from src.clients.otx_client import OTXClient
from src.clients.misp_client import MISPClient
from src.cache import EnrichmentCache

logger = logging.getLogger("enrichment")


class EnrichmentEngine:

    def __init__(self, config):
        self.config = config
        self.thresholds = config["thresholds"]

        self.abuseipdb = AbuseIPDBClient(
            api_key=config["abuseipdb"]["api_key"],
            url=config["abuseipdb"]["url"]
        )

        self.otx = OTXClient(
            api_key=config["otx"]["api_key"],
            url=config["otx"]["url"]
        )

        self.misp = MISPClient(
            api_key=config["misp"]["api_key"],
            url=config["misp"]["url"],
            verify_ssl=config["misp"]["verify_ssl"]
        )

        self.cache = EnrichmentCache()

        logger.info("Enrichment engine initialized with 3 sources + cache")

    def enrich_ip(self, ip):
        cached = self.cache.get(ip)
        if cached:
            logger.info(f"Using cached result for {ip}")
            return cached

        logger.info(f"Enriching IP: {ip}")

        abuse_result = self.abuseipdb.check_ip(ip)
        otx_result = self.otx.check_ip(ip)
        misp_result = self.misp.check_ip(ip)

        sources_responding = 0
        if abuse_result:
            sources_responding += 1
        if otx_result:
            sources_responding += 1
        if misp_result:
            sources_responding += 1

        abuse_score = abuse_result["score"] if abuse_result else 0
        otx_pulses = otx_result["pulse_count"] if otx_result else 0
        misp_matched = misp_result["matched"] if misp_result else False

        verdict = self.calculate_verdict(abuse_score, otx_pulses, misp_matched)

        enrichment = {
            "ip": ip,
            "verdict": verdict,
            "sources_responding": sources_responding,
            "abuseipdb": abuse_result,
            "otx": otx_result,
            "misp": misp_result,
            "summary": {
                "abuse_score": abuse_score,
                "otx_pulses": otx_pulses,
                "misp_matched": misp_matched
            }
        }

        self.cache.set(ip, enrichment)

        logger.info(f"Enrichment complete: {ip} verdict={verdict} "
                     f"(abuse={abuse_score}, otx={otx_pulses}, misp={misp_matched})")

        return enrichment

    def calculate_verdict(self, abuse_score, otx_pulses, misp_matched):
        block_score = self.thresholds["block_score"]
        review_score = self.thresholds["review_score"]

        if abuse_score >= block_score and (otx_pulses > 0 or misp_matched):
            return "BLOCK"
        elif abuse_score >= block_score:
            return "LIKELY_MALICIOUS"
        elif abuse_score >= review_score:
            return "REVIEW"
        elif otx_pulses > 0 or misp_matched:
            return "SUSPICIOUS"
        else:
            return "CLEAN"

    def enrich_hash(self, file_hash):
        cache_key = f"hash:{file_hash}"
        cached = self.cache.get(cache_key)
        if cached:
            logger.info(f"Using cached result for hash {file_hash}")
            return cached

        logger.info(f"Enriching hash: {file_hash}")

        otx_result = self.otx.check_hash(file_hash)
        misp_result = self.misp.check_hash(file_hash)

        sources_responding = 0
        if otx_result:
            sources_responding += 1
        if misp_result:
            sources_responding += 1

        otx_pulses = otx_result["pulse_count"] if otx_result else 0
        misp_matched = misp_result["matched"] if misp_result else False

        verdict = self.calculate_hash_verdict(otx_pulses, misp_matched)

        enrichment = {
            "hash": file_hash,
            "verdict": verdict,
            "sources_responding": sources_responding,
            "otx": otx_result,
            "misp": misp_result,
            "summary": {
                "otx_pulses": otx_pulses,
                "misp_matched": misp_matched
            }
        }

        self.cache.set(cache_key, enrichment)

        logger.info(f"Hash enrichment complete: {file_hash} verdict={verdict} "
                     f"(otx={otx_pulses}, misp={misp_matched})")

        return enrichment

    def calculate_hash_verdict(self, otx_pulses, misp_matched):
        if otx_pulses > 0 and misp_matched:
            return "BLOCK"
        elif otx_pulses > 0 or misp_matched:
            return "LIKELY_MALICIOUS"
        else:
            return "CLEAN"

import pytest
from src.enrichment import EnrichmentEngine
from src.config import load_config
from src.logger import setup_logger


logger = setup_logger()


class TestHashVerdict:

    def setup_method(self):
        config = load_config()
        self.engine = EnrichmentEngine(config)

    def test_both_sources_match_returns_block(self):
        verdict = self.engine.calculate_hash_verdict(
            otx_pulses=10, misp_matched=True
        )
        assert verdict == "BLOCK"

    def test_only_otx_returns_likely_malicious(self):
        verdict = self.engine.calculate_hash_verdict(
            otx_pulses=5, misp_matched=False
        )
        assert verdict == "LIKELY_MALICIOUS"

    def test_only_misp_returns_likely_malicious(self):
        verdict = self.engine.calculate_hash_verdict(
            otx_pulses=0, misp_matched=True
        )
        assert verdict == "LIKELY_MALICIOUS"

    def test_no_matches_returns_clean(self):
        verdict = self.engine.calculate_hash_verdict(
            otx_pulses=0, misp_matched=False
        )
        assert verdict == "CLEAN"

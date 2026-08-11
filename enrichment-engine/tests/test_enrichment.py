import pytest
from src.enrichment import EnrichmentEngine
from src.config import load_config
from src.logger import setup_logger
from src.main import extract_ip


logger = setup_logger()


class TestExtractIP:

    def test_linux_alert_srcip(self):
        alert = {"data": {"srcip": "45.148.10.174"}}
        assert extract_ip(alert) == "45.148.10.174"

    def test_windows_alert_sourceip(self):
        alert = {"data": {"win": {"eventdata": {"sourceIp": "10.0.0.1"}}}}
        assert extract_ip(alert) == "10.0.0.1"

    def test_no_ip_returns_none(self):
        alert = {"data": {}}
        assert extract_ip(alert) is None

    def test_empty_alert_returns_none(self):
        alert = {}
        assert extract_ip(alert) is None

    def test_srcip_empty_string(self):
        alert = {"data": {"srcip": ""}}
        assert extract_ip(alert) is None


class TestVerdict:

    def setup_method(self):
        config = load_config()
        self.engine = EnrichmentEngine(config)

    def test_high_abuse_with_otx_returns_block(self):
        verdict = self.engine.calculate_verdict(
            abuse_score=90, otx_pulses=5, misp_matched=False
        )
        assert verdict == "BLOCK"

    def test_high_abuse_with_misp_returns_block(self):
        verdict = self.engine.calculate_verdict(
            abuse_score=80, otx_pulses=0, misp_matched=True
        )
        assert verdict == "BLOCK"

    def test_high_abuse_alone_returns_likely_malicious(self):
        verdict = self.engine.calculate_verdict(
            abuse_score=90, otx_pulses=0, misp_matched=False
        )
        assert verdict == "LIKELY_MALICIOUS"

    def test_medium_abuse_returns_review(self):
        verdict = self.engine.calculate_verdict(
            abuse_score=60, otx_pulses=0, misp_matched=False
        )
        assert verdict == "REVIEW"

    def test_low_abuse_with_otx_returns_suspicious(self):
        verdict = self.engine.calculate_verdict(
            abuse_score=10, otx_pulses=3, misp_matched=False
        )
        assert verdict == "SUSPICIOUS"

    def test_low_abuse_with_misp_returns_suspicious(self):
        verdict = self.engine.calculate_verdict(
            abuse_score=0, otx_pulses=0, misp_matched=True
        )
        assert verdict == "SUSPICIOUS"

    def test_no_indicators_returns_clean(self):
        verdict = self.engine.calculate_verdict(
            abuse_score=0, otx_pulses=0, misp_matched=False
        )
        assert verdict == "CLEAN"

    def test_boundary_75_without_confirmation(self):
        verdict = self.engine.calculate_verdict(
            abuse_score=75, otx_pulses=0, misp_matched=False
        )
        assert verdict == "LIKELY_MALICIOUS"

    def test_boundary_50_returns_review(self):
        verdict = self.engine.calculate_verdict(
            abuse_score=50, otx_pulses=0, misp_matched=False
        )
        assert verdict == "REVIEW"

    def test_boundary_49_returns_clean(self):
        verdict = self.engine.calculate_verdict(
            abuse_score=49, otx_pulses=0, misp_matched=False
        )
        assert verdict == "CLEAN"

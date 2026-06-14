import sys
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import MagicMock, patch

from collector.base import RawRule
from collector.mock_provider import MockMISPRuleProvider
from processors.deduplicator import compute_hash, is_duplicate
from processors.sigma_converter import convert_sigma_to_wazuh, _mock_sigma_to_wazuh
from validators import RuleValidator, validate_yara, validate_sigma, validate_wazuh


class TestMockMISPRuleProvider(unittest.TestCase):
    def setUp(self):
        # Resolve fixtures path relative to project root
        self.fixture_path = Path(__file__).resolve().parent.parent.parent / "fixtures" / "mock_rules.json"
        self.provider = MockMISPRuleProvider(fixture_path=self.fixture_path)

    def test_fetch_rules_all(self):
        rules = self.provider.fetch_rules(
            rule_types=["yara", "sigma", "wazuh"],
            tags=["tlp:white"]
        )
        self.assertEqual(len(rules), 3)
        self.assertEqual(rules[0].rule_type, "yara")
        self.assertEqual(rules[1].rule_type, "sigma")
        self.assertEqual(rules[2].rule_type, "wazuh")

    def test_fetch_rules_filter_type(self):
        rules = self.provider.fetch_rules(
            rule_types=["wazuh"],
            tags=["tlp:white"]
        )
        self.assertEqual(len(rules), 1)
        self.assertEqual(rules[0].rule_type, "wazuh")

    def test_fetch_rules_since(self):
        since = datetime.fromisoformat("2026-06-14T09:02:00+00:00")
        rules = self.provider.fetch_rules(
            rule_types=["yara", "sigma", "wazuh"],
            tags=["tlp:white"],
            since=since
        )
        # 1002 and 1003 are after 09:02:00
        self.assertEqual(len(rules), 2)


class TestValidators(unittest.TestCase):
    @patch("subprocess.run")
    def test_validate_yara_success(self, mock_run):
        mock_res = MagicMock()
        mock_res.returncode = 0
        mock_res.stderr = ""
        mock_run.return_value = mock_res

        res = validate_yara("rule test { condition: true }")
        self.assertTrue(res.valid)
        self.assertEqual(len(res.errors), 0)

    @patch("subprocess.run")
    def test_validate_yara_failure(self, mock_run):
        mock_res = MagicMock()
        mock_res.returncode = 1
        mock_res.stderr = "error on line 2: syntax error"
        mock_run.return_value = mock_res

        res = validate_yara("rule test { invalid }")
        self.assertFalse(res.valid)
        self.assertIn("error on line 2: syntax error", res.errors)

    @patch("subprocess.run")
    def test_validate_sigma_success(self, mock_run):
        mock_res = MagicMock()
        mock_res.returncode = 0
        mock_res.stderr = ""
        mock_run.return_value = mock_res

        res = validate_sigma("title: Test Sigma\nlogsource:\n  product: windows\ndetection:\n  sel:\n    EventID: 1\n  condition: sel")
        self.assertTrue(res.valid)

    @patch("subprocess.run")
    def test_validate_wazuh_success(self, mock_run):
        mock_res = MagicMock()
        mock_res.returncode = 0
        mock_res.stderr = ""
        mock_run.return_value = mock_res

        res = validate_wazuh("<group name='syslog'><rule id='100201' level='5'><description>test</description></rule></group>")
        self.assertTrue(res.valid)

    @patch("subprocess.run")
    def test_validator_dispatcher(self, mock_run):
        mock_res = MagicMock()
        mock_res.returncode = 0
        mock_run.return_value = mock_res

        dispatcher = RuleValidator()
        rule = RawRule(
            rule_type="yara",
            name="test.yar",
            content="test content",
            event_id=1,
            event_uuid="abc",
            misp_timestamp=datetime.now(timezone.utc),
            tags=[]
        )
        res = dispatcher.validate(rule)
        self.assertTrue(res.valid)


class TestProcessors(unittest.TestCase):
    def test_deduplicator(self):
        content = "rule unique_test { condition: true }"
        h = compute_hash(content)
        existing = {h}
        
        self.assertTrue(is_duplicate(content, existing))
        self.assertFalse(is_duplicate("other content", existing))

    @patch("subprocess.run")
    def test_sigma_converter_cli(self, mock_run):
        mock_res = MagicMock()
        mock_res.returncode = 0
        mock_res.stdout = "<group name='converted'><rule id='100299'></rule></group>"
        mock_run.return_value = mock_res

        xml = convert_sigma_to_wazuh("sigma rules content", "test.yml")
        self.assertIn("converted", xml)

    def test_sigma_mock_fallback(self):
        sigma_yml = "title: Process Creation\nlevel: high"
        xml = _mock_sigma_to_wazuh(sigma_yml, "test_mock.yml")
        self.assertIn("<group name=\"sigma,misp,\">", xml)
        self.assertIn("Process Creation [Sigma converted]", xml)
        self.assertIn("level=\"10\"", xml)  # high maps to 10

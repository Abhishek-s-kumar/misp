import sys
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import MagicMock, patch

from collector.base import RawRule
from collector.mock_provider import MockMISPRuleProvider
from processors.deduplicator import (
    compute_hash,
    is_duplicate,
    compute_sigma_hash,
    compute_yara_hash,
    compute_wazuh_hash,
)
from processors.sigma_converter import convert_sigma_to_wazuh, _mock_sigma_to_wazuh
from processors.xml_merger import (
    next_available_id,
    get_or_assign_sigma_id,
    merge_wazuh_xml_files,
    override_xml_rule_ids,
    rebuild_local_rules,
)
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

    def test_compute_sigma_hash(self):
        # Nested keys & different ordering must produce the same hash
        sigma_yml1 = """
title: Test Rule
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: [1, 2]
    Image|endswith: \\cmd.exe
"""
        sigma_yml2 = """
title: Test Rule
detection:
  selection:
    Image|endswith: \\cmd.exe
    EventID: [1, 2]
logsource:
  service: security
  product: windows
"""
        hash1 = compute_sigma_hash(sigma_yml1)
        hash2 = compute_sigma_hash(sigma_yml2)
        self.assertEqual(hash1, hash2)

        # Different contents must produce a different hash
        sigma_yml3 = """
title: Test Rule 2
logsource:
  product: windows
"""
        self.assertNotEqual(hash1, compute_sigma_hash(sigma_yml3))

    def test_compute_yara_hash(self):
        yara_rule1 = """
rule suspicious_yara {
    meta:
        author = "misp" // comment
    strings:
        $a = "cmd"
    condition:
        $a
}
"""
        # Whitespace and comments stripped, same rule structure
        yara_rule2 = """
rule suspicious_yara {
    /* block comment */
    meta:
        author = "misp"
    strings:
        $a = "cmd"
    condition:
        $a
}
"""
        self.assertEqual(compute_yara_hash(yara_rule1), compute_yara_hash(yara_rule2))

    def test_compute_wazuh_hash(self):
        # Identical rules with different IDs must have different hashes
        wazuh_rule1 = "<rule id='100001' level='5'><description>test</description></rule>"
        wazuh_rule2 = "<rule id='100002' level='5'><description>test</description></rule>"
        self.assertNotEqual(compute_wazuh_hash(wazuh_rule1), compute_wazuh_hash(wazuh_rule2))

        # Whitespaces and comments normalization
        wazuh_rule3 = """
<!-- some comment -->
<rule id='100001' level='5'>
    <description>test</description>
</rule>
"""
        self.assertEqual(compute_wazuh_hash(wazuh_rule1), compute_wazuh_hash(wazuh_rule3))

    @patch("subprocess.run")
    def test_wazuh_validator_missing_binary(self, mock_run):
        mock_run.side_effect = FileNotFoundError()
        rule = RawRule(
            rule_type="wazuh",
            name="test.xml",
            content="<rule id='100001'></rule>",
            event_id=1,
            event_uuid="abc",
            misp_timestamp=datetime.now(timezone.utc),
            tags=[]
        )
        res = validate_wazuh(rule.content)
        self.assertTrue(res.valid)
        self.assertIn("wazuh-analysisd not available", res.warnings[0])


class TestXMLMerger(unittest.TestCase):

    def test_next_available_id_basic(self):
        used = {200000, 200001, 200002}
        nid = next_available_id(used)
        self.assertEqual(nid, 200003)
        self.assertIn(200003, used)  # also mutates used_ids

    def test_next_available_id_fills_gaps(self):
        used = {200000, 200002}
        nid = next_available_id(used)
        self.assertEqual(nid, 200001)

    def test_next_available_id_exhausted(self):
        used = set(range(200000, 300000))
        with self.assertRaises(ValueError):
            next_available_id(used)

    def test_sigma_id_persistence_assigns_new(self, tmp_path=None):
        import tempfile, yaml
        with tempfile.TemporaryDirectory() as tmpdir:
            sigma_file = Path(tmpdir) / "test.yml"
            sigma_file.write_text(
                "title: Test\nlogsource:\n  product: windows\ndetection:\n  condition: true\n",
                encoding="utf-8"
            )
            used = set()
            rid = get_or_assign_sigma_id(sigma_file, used)
            self.assertGreaterEqual(rid, 200000)
            self.assertLessEqual(rid, 299999)
            self.assertIn(rid, used)

            # Re-read: must return the same ID
            rid2 = get_or_assign_sigma_id(sigma_file, used)
            self.assertEqual(rid, rid2)

    def test_sigma_id_persistence_reuses_existing(self):
        import tempfile, yaml
        with tempfile.TemporaryDirectory() as tmpdir:
            sigma_file = Path(tmpdir) / "test.yml"
            sigma_file.write_text(
                "title: Test\ncustom:\n  wazuh_rule_id: 100042\ndetection:\n  condition: true\n",
                encoding="utf-8"
            )
            used = set()
            rid = get_or_assign_sigma_id(sigma_file, used)
            self.assertEqual(rid, 100042)

    def test_merge_wazuh_xml_files_basic(self):
        rule1 = "<rule id='100010' level='3'><description>Test 1</description></rule>"
        rule2 = "<rule id='100011' level='5'><description>Test 2</description></rule>"
        merged = merge_wazuh_xml_files([rule1, rule2])
        self.assertIn("100010", merged)
        self.assertIn("100011", merged)
        self.assertIn('<group name="misp,">', merged)

    def test_merge_wazuh_xml_files_detects_duplicate_id(self):
        rule = "<rule id='100010' level='3'><description>Test</description></rule>"
        with self.assertRaises(ValueError) as ctx:
            merge_wazuh_xml_files([rule, rule])
        self.assertIn("Duplicate rule ID", str(ctx.exception))

    def test_merge_wazuh_xml_files_rejects_malformed(self):
        malformed = "<rule id='100010' level='3'><description>unclosed"
        with self.assertRaises(ValueError) as ctx:
            merge_wazuh_xml_files([malformed])
        self.assertIn("Malformed XML", str(ctx.exception))

    def test_override_xml_rule_ids(self):
        xml = "<group name='test'><rule id='999' level='3'><description>t</description></rule></group>"
        result = override_xml_rule_ids(xml, 100055)
        self.assertIn('id="100055"', result)
        self.assertNotIn('id="999"', result)

    @patch("subprocess.run")
    def test_rebuild_local_rules(self, mock_run):
        import tempfile, yaml
        mock_res = MagicMock()
        mock_res.returncode = 0
        mock_res.stdout = "<group name='sigma,misp,'><rule id='100201' level='3'><description>x</description></rule></group>"
        mock_res.stderr = ""
        mock_run.return_value = mock_res

        with tempfile.TemporaryDirectory() as tmpdir:
            rules_dir = Path(tmpdir) / "rules"
            (rules_dir / "wazuh").mkdir(parents=True)
            (rules_dir / "sigma").mkdir(parents=True)
            (rules_dir / "yara").mkdir(parents=True)

            # Add a wazuh rule
            (rules_dir / "wazuh" / "test.xml").write_text(
                "<rule id='100010' level='3'><description>wazuh rule</description></rule>",
                encoding="utf-8"
            )

            rebuild_local_rules(rules_dir)
            out = (Path(tmpdir) / "generated" / "local_rules.xml").read_text()
            self.assertIn("100010", out)
            self.assertIn('<group name="misp,">', out)


class TestGitOps(unittest.TestCase):
    """Tests for processors/git_ops.py PR reuse/create logic."""

    @patch("processors.git_ops._run")
    def test_get_or_create_pr_reuses_existing(self, mock_run):
        """When gh pr list returns an open PR, it should be reused."""
        import json, tempfile
        from processors.git_ops import get_or_create_pr

        existing_pr = [{"number": 7, "url": "https://github.com/org/repo/pull/7", "title": "sync: old"}]
        mock_run.return_value = MagicMock(stdout=json.dumps(existing_pr), returncode=0)

        with tempfile.TemporaryDirectory() as tmpdir:
            result = get_or_create_pr(Path(tmpdir))

        self.assertEqual(result["action"], "reused")
        self.assertEqual(result["number"], 7)
        self.assertIn("pull/7", result["url"])

    @patch("processors.git_ops._run")
    def test_get_or_create_pr_creates_new(self, mock_run):
        """When gh pr list returns empty, a new PR should be created."""
        import tempfile
        from processors.git_ops import get_or_create_pr

        def side_effect(cmd, **kwargs):
            if "list" in cmd:
                return MagicMock(stdout="[]", returncode=0)
            if "create" in cmd:
                return MagicMock(stdout="https://github.com/org/repo/pull/8\n", returncode=0)

        mock_run.side_effect = side_effect

        with tempfile.TemporaryDirectory() as tmpdir:
            result = get_or_create_pr(Path(tmpdir))

        self.assertEqual(result["action"], "created")
        self.assertIn("pull/8", result["url"])

    @patch("processors.git_ops._run")
    def test_get_or_create_pr_handles_gh_error(self, mock_run):
        """When gh is not available, an error dict should be returned."""
        import tempfile
        from processors.git_ops import get_or_create_pr

        mock_run.side_effect = FileNotFoundError("gh: not found")

        with tempfile.TemporaryDirectory() as tmpdir:
            result = get_or_create_pr(Path(tmpdir))

        self.assertEqual(result["action"], "error")
        self.assertIsNone(result["url"])


class TestCheckRuleIds(unittest.TestCase):
    """Tests for DaC/check_rule_ids.py extractor functions."""

    def _import(self):
        import importlib.util, sys
        spec = importlib.util.spec_from_file_location(
            "check_rule_ids",
            Path("/home/kali/Desktop/misp/DaC/check_rule_ids.py"),
        )
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod

    def test_extract_ids_from_xml(self):
        mod = self._import()
        content = "<rule id='100010' level='3'><description>t</description></rule>"
        ids = mod.extract_ids_from_xml(content)
        self.assertEqual(ids, [100010])

    def test_extract_ids_from_xml_malformed(self):
        mod = self._import()
        ids = mod.extract_ids_from_xml("<rule id='100010' level='3'><desc>unclosed")
        self.assertEqual(ids, [])  # Parse error handled gracefully

    def test_extract_ids_from_sigma(self):
        mod = self._import()
        content = "title: Test\ncustom:\n  wazuh_rule_id: 100042\n"
        ids = mod.extract_ids_from_sigma(content)
        self.assertEqual(ids, [100042])

    def test_extract_ids_from_sigma_no_custom(self):
        mod = self._import()
        content = "title: Test\ndetection:\n  condition: true\n"
        ids = mod.extract_ids_from_sigma(content)
        self.assertEqual(ids, [])

    def test_yara_file_returns_no_ids(self):
        mod = self._import()
        yara_content = "rule suspicious { condition: true }"
        ids = mod.extract_ids_from_file(Path("rules/yara/test.yar"), yara_content)
        self.assertEqual(ids, [])

    def test_detect_duplicates(self):
        mod = self._import()
        dups = mod.detect_duplicates([100010, 100011, 100010])
        self.assertIn(100010, dups)
        self.assertNotIn(100011, dups)

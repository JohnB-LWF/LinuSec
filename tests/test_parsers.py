import importlib.util
import pathlib
import unittest

PROJECT_ROOT = pathlib.Path(__file__).resolve().parents[1]
MODULES_DIR = PROJECT_ROOT / "modules"
SAMPLE_DIR = PROJECT_ROOT / "tests" / "sample_raw"


def load_module(module_name, file_name):
    module_path = MODULES_DIR / file_name
    spec = importlib.util.spec_from_file_location(module_name, module_path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class ExplanationFieldsMixin:
    """Shared assertions for the new explanation-rich report fields."""

    def assert_explanation_fields(self, report):
        self.assertIn("risk_score", report, "report must include risk_score")
        self.assertIn("severity_reason", report, "report must include severity_reason")
        self.assertIn("triggered_rules", report, "report must include triggered_rules")
        self.assertIn("thresholds", report, "report must include thresholds")
        self.assertIn("remediation", report, "report must include remediation")

        self.assertIsInstance(report["risk_score"], int)
        self.assertGreaterEqual(report["risk_score"], 0)
        self.assertLessEqual(report["risk_score"], 100)

        self.assertIsInstance(report["severity_reason"], str)
        self.assertGreater(len(report["severity_reason"]), 0)

        self.assertIsInstance(report["triggered_rules"], list)
        self.assertIsInstance(report["thresholds"], dict)
        self.assertIsInstance(report["remediation"], list)

        for step in report["remediation"]:
            self.assertIn("description", step)
            self.assertIn("command", step)
            self.assertIn("impact", step)

    def assert_risk_score_matches_severity(self, report):
        score = report["risk_score"]
        severity = report["severity"]
        if severity == "high":
            self.assertGreaterEqual(score, 67, f"HIGH severity must have risk_score >= 67, got {score}")
        elif severity == "medium":
            self.assertGreater(score, 0, "MEDIUM severity must have risk_score > 0")
            self.assertLess(score, 100, "MEDIUM severity must have risk_score < 100")
        elif severity == "low":
            self.assertEqual(score, 0, "LOW severity must have risk_score == 0")


class SystemParserTests(unittest.TestCase, ExplanationFieldsMixin):
    def setUp(self):
        self.mod = load_module("system_module", "system.py")

    def test_parser_extracts_fields(self):
        raw = (SAMPLE_DIR / "system_raw.txt").read_text(encoding="utf-8")
        parsed = self.mod.parse_system_raw(raw)
        self.assertEqual(parsed["hostname"], "wsl-host")
        self.assertEqual(parsed["os"], "Ubuntu 24.04 LTS")
        self.assertGreater(len(parsed["upgradable_packages"]), 0)

    def test_severity_and_metrics(self):
        raw = (SAMPLE_DIR / "system_raw.txt").read_text(encoding="utf-8")
        parsed = self.mod.parse_system_raw(raw)
        report = self.mod.build_report(parsed)
        self.assertIn(report["severity"], {"medium", "high"})
        self.assertIn("upgradable_count", report["metrics"])
        self.assertGreater(report["metrics"]["upgradable_count"], 0)

    def test_explanation_fields_present(self):
        raw = (SAMPLE_DIR / "system_raw.txt").read_text(encoding="utf-8")
        parsed = self.mod.parse_system_raw(raw)
        report = self.mod.build_report(parsed)
        self.assert_explanation_fields(report)

    def test_risk_score_matches_severity(self):
        raw = (SAMPLE_DIR / "system_raw.txt").read_text(encoding="utf-8")
        parsed = self.mod.parse_system_raw(raw)
        report = self.mod.build_report(parsed)
        self.assert_risk_score_matches_severity(report)

    def test_triggered_rules_populated_when_upgradable(self):
        raw = (SAMPLE_DIR / "system_raw.txt").read_text(encoding="utf-8")
        parsed = self.mod.parse_system_raw(raw)
        report = self.mod.build_report(parsed)
        self.assertGreater(len(report["triggered_rules"]), 0)

    def test_low_severity_has_zero_risk_score(self):
        parsed = {
            "hostname": "test", "os": "Ubuntu", "kernel": "5.x", "uptime": "up 1 hour",
            "upgradable_packages": [],
        }
        report = self.mod.build_report(parsed)
        self.assertEqual(report["severity"], "low")
        self.assertEqual(report["risk_score"], 0)
        self.assertEqual(report["triggered_rules"], [])


class PermissionsParserTests(unittest.TestCase, ExplanationFieldsMixin):
    def setUp(self):
        self.mod = load_module("permissions_module", "permissions.py")

    def test_parser_extracts_sections(self):
        raw = (SAMPLE_DIR / "permissions_raw.txt").read_text(encoding="utf-8")
        parsed = self.mod.parse_permissions_raw(raw)
        self.assertEqual(len(parsed["world_writable_dirs"]), 2)
        self.assertEqual(len(parsed["insecure_homes"]), 1)
        self.assertEqual(len(parsed["suid"]), 2)
        self.assertEqual(len(parsed["sgid"]), 1)

    def test_severity_high_due_to_insecure_home(self):
        raw = (SAMPLE_DIR / "permissions_raw.txt").read_text(encoding="utf-8")
        parsed = self.mod.parse_permissions_raw(raw)
        report = self.mod.build_report(parsed)
        self.assertEqual(report["severity"], "high")
        self.assertEqual(report["metrics"]["insecure_home_dir_count"], 1)
        self.assertEqual(report["metrics"]["world_writable_dir_count"], 2)

    def test_explanation_fields_present(self):
        raw = (SAMPLE_DIR / "permissions_raw.txt").read_text(encoding="utf-8")
        parsed = self.mod.parse_permissions_raw(raw)
        report = self.mod.build_report(parsed)
        self.assert_explanation_fields(report)

    def test_risk_score_matches_severity(self):
        raw = (SAMPLE_DIR / "permissions_raw.txt").read_text(encoding="utf-8")
        parsed = self.mod.parse_permissions_raw(raw)
        report = self.mod.build_report(parsed)
        self.assert_risk_score_matches_severity(report)

    def test_triggered_rules_mention_insecure_home(self):
        raw = (SAMPLE_DIR / "permissions_raw.txt").read_text(encoding="utf-8")
        parsed = self.mod.parse_permissions_raw(raw)
        report = self.mod.build_report(parsed)
        self.assertTrue(
            any("insecure_home" in r for r in report["triggered_rules"]),
            "triggered_rules must mention insecure_home_dir_count"
        )

    def test_clean_system_scores_low(self):
        parsed = {"suid": [], "sgid": [], "world_writable_dirs": [], "insecure_homes": []}
        report = self.mod.build_report(parsed)
        self.assertEqual(report["severity"], "low")
        self.assertEqual(report["risk_score"], 0)
        self.assertEqual(report["triggered_rules"], [])


class LogsParserTests(unittest.TestCase, ExplanationFieldsMixin):
    def setUp(self):
        self.mod = load_module("logs_module", "logs.py")

    def test_parser_extracts_sections(self):
        raw = (SAMPLE_DIR / "logs_raw.txt").read_text(encoding="utf-8")
        parsed = self.mod.parse_logs_raw(raw)
        self.assertEqual(len(parsed["failed_logins"]), 3)
        self.assertEqual(len(parsed["sudo_failures"]), 2)
        self.assertEqual(len(parsed["kernel_errors"]), 2)

    def test_severity_medium_with_low_counts(self):
        raw = (SAMPLE_DIR / "logs_raw.txt").read_text(encoding="utf-8")
        parsed = self.mod.parse_logs_raw(raw)
        report = self.mod.build_report(parsed)
        self.assertEqual(report["severity"], "medium")
        self.assertEqual(report["metrics"]["failed_login_count"], 3)
        self.assertEqual(report["metrics"]["sudo_failure_count"], 2)
        self.assertEqual(report["metrics"]["kernel_error_count"], 2)

    def test_explanation_fields_present(self):
        raw = (SAMPLE_DIR / "logs_raw.txt").read_text(encoding="utf-8")
        parsed = self.mod.parse_logs_raw(raw)
        report = self.mod.build_report(parsed)
        self.assert_explanation_fields(report)

    def test_risk_score_matches_severity(self):
        raw = (SAMPLE_DIR / "logs_raw.txt").read_text(encoding="utf-8")
        parsed = self.mod.parse_logs_raw(raw)
        report = self.mod.build_report(parsed)
        self.assert_risk_score_matches_severity(report)

    def test_high_severity_triggered_by_volume(self):
        parsed = {
            "failed_logins": ["line"] * 30,
            "sudo_failures": [],
            "kernel_errors": [],
        }
        report = self.mod.build_report(parsed)
        self.assertEqual(report["severity"], "high")
        self.assertGreaterEqual(report["risk_score"], 67)

    def test_clean_system_scores_low(self):
        parsed = {"failed_logins": [], "sudo_failures": [], "kernel_errors": []}
        report = self.mod.build_report(parsed)
        self.assertEqual(report["severity"], "low")
        self.assertEqual(report["risk_score"], 0)
        self.assertEqual(report["triggered_rules"], [])


if __name__ == "__main__":
    unittest.main()
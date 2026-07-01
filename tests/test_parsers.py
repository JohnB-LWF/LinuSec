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


class ParserTests(unittest.TestCase):
    def setUp(self):
        self.system_module = load_module("system_module", "system.py")
        self.permissions_module = load_module("permissions_module", "permissions.py")
        self.logs_module = load_module("logs_module", "logs.py")

    def test_system_parser_and_severity(self):
        raw_text = (SAMPLE_DIR / "system_raw.txt").read_text(encoding="utf-8")
        parsed = self.system_module.parse_system_raw(raw_text)
        report = self.system_module.build_report(parsed)

        self.assertEqual(parsed["hostname"], "wsl-host")
        self.assertGreater(parsed["upgradable_packages"].__len__(), 0)
        self.assertIn(report["severity"], {"medium", "high"})
        self.assertIn("upgradable_count", report["metrics"])

    def test_permissions_parser_and_severity(self):
        raw_text = (SAMPLE_DIR / "permissions_raw.txt").read_text(encoding="utf-8")
        parsed = self.permissions_module.parse_permissions_raw(raw_text)
        report = self.permissions_module.build_report(parsed)

        self.assertEqual(len(parsed["world_writable_dirs"]), 2)
        self.assertEqual(len(parsed["insecure_homes"]), 1)
        self.assertEqual(report["severity"], "high")
        self.assertEqual(report["metrics"]["insecure_home_dir_count"], 1)

    def test_logs_parser_and_severity(self):
        raw_text = (SAMPLE_DIR / "logs_raw.txt").read_text(encoding="utf-8")
        parsed = self.logs_module.parse_logs_raw(raw_text)
        report = self.logs_module.build_report(parsed)

        self.assertEqual(len(parsed["failed_logins"]), 3)
        self.assertEqual(len(parsed["sudo_failures"]), 2)
        self.assertEqual(len(parsed["kernel_errors"]), 2)
        self.assertEqual(report["severity"], "medium")


if __name__ == "__main__":
    unittest.main()

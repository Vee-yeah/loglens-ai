import os
import unittest
from unittest.mock import patch

from src.analyzer import analyze_log, redact_secrets


class AnalyzerTests(unittest.TestCase):
    def test_detects_connection_refused(self):
        with patch.dict(os.environ, {"OPENAI_API_KEY": ""}, clear=False):
            result = analyze_log("java.net.ConnectException: Connection refused")
        self.assertEqual(result.mode, "Local rule-based")
        self.assertEqual(result.findings[0]["Signal"], "Connection refused")
        self.assertEqual(result.findings[0]["Line number(s)"], "1")

    def test_reports_actual_matching_line_number(self):
        log = "INFO Startup complete\nWARN Retrying\nERROR Connection refused"
        with patch.dict(os.environ, {"OPENAI_API_KEY": ""}, clear=False):
            result = analyze_log(log)
        self.assertEqual(result.findings[0]["Line number(s)"], "3")

    def test_redacts_common_secrets(self):
        text = "api_key=super-secret Bearer abc.def-123 password: hunter2"
        self.assertNotIn("super-secret", redact_secrets(text))
        self.assertNotIn("abc.def-123", redact_secrets(text))
        self.assertNotIn("hunter2", redact_secrets(text))


if __name__ == "__main__":
    unittest.main()

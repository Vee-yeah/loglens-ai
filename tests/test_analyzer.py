import os
import unittest
from unittest.mock import patch

from src.analyzer import _api_error_message, _detect_technologies, _rag_findings, analyze_log, redact_secrets
from src.rag import KnowledgeMatch, RetrievalResult, compact_search_query, retrieve_from_oracle


class AnalyzerTests(unittest.TestCase):
    @staticmethod
    def _connection_runbook():
        return KnowledgeMatch(
            technology="Java/JVM", error_code="ConnectException", title="Connection refused",
            description="The target service rejected a TCP connection.", likely_causes="Service is down.",
            remediation="Verify host, port, and service health.", verification="Connect successfully.",
            source_url=None, match_terms="ConnectException|Connection refused", score=100,
        )

    def test_rag_match_becomes_a_finding(self):
        match = self._connection_runbook()
        findings = _rag_findings("java.net.ConnectException: Connection refused", [match])
        self.assertEqual(findings[0]["Signal"], "Connection refused")
        self.assertEqual(findings[0]["Line number(s)"], "1")

    def test_rag_finding_reports_actual_matching_line_number(self):
        log = "INFO Startup complete\nWARN Retrying\nERROR Connection refused"
        findings = _rag_findings(log, [self._connection_runbook()])
        self.assertEqual(findings[0]["Line number(s)"], "3")

    def test_no_rag_match_does_not_use_hidden_python_rules(self):
        log = "ClassNotFoundException: com.acme.Driver\nKeyError: 'email'\nERROR: duplicate key value violates unique constraint"
        with patch("src.analyzer.retrieve_from_oracle", return_value=RetrievalResult([], "Oracle RAG (0 match(es), 0.1s)")), patch.dict(os.environ, {"OPENAI_API_KEY": ""}, clear=False):
            result = analyze_log(log)
        self.assertEqual(result.findings, [])
        self.assertEqual(result.mode, "No RAG match + local diagnostics")

    def test_oracle_unique_constraint_reports_constraint_and_source_line(self):
        log = (
            "ORA-00001: unique constraint (SCHEMA.CONSTRAINT_NAME) violated\n"
            'ORA-06512: at "SCHEMA.PROCEDURE_NAME", line 78\n'
        )
        with patch.dict(os.environ, {"OPENAI_API_KEY": ""}, clear=False):
            result = analyze_log(log)
        self.assertIn("`SCHEMA.CONSTRAINT_NAME`", result.answer)
        self.assertIn("line **78**", result.answer)
        self.assertIn("all_cons_columns", result.answer.lower())

    def test_oracle_missing_table_reports_source_lookup(self):
        log = (
            "ORA-00942: table or view does not exist\n"
            'ORA-06512: at "SCHEMA.PACKAGE_NAME", line 45\n'
            'ORA-06512: at "SCHEMA.TRIGGER_NAME", line 12\n'
        )
        with patch.dict(os.environ, {"OPENAI_API_KEY": ""}, clear=False):
            result = analyze_log(log)
        self.assertIn("missing table/view name is **not present", result.answer)
        self.assertIn("`SCHEMA.PACKAGE_NAME`", result.answer)
        self.assertIn("all_source", result.answer.lower())

    def test_detects_multiple_technology_log_formats(self):
        log = "Traceback (most recent call last):\nFile \"job.py\", line 18\nORA-00001: unique constraint"
        technologies = _detect_technologies(log)
        self.assertIn("Python", technologies)
        self.assertIn("Oracle SQL/PLSQL", technologies)

    def test_api_limit_message_explains_credit_exhaustion(self):
        error = type("ApiError", (Exception,), {"code": "credit_balance_exhausted", "status_code": 429})()
        message = _api_error_message(error)
        self.assertIn("HTTP 429", message)
        self.assertIn("Add credits", message)

    def test_redacts_common_secrets(self):
        text = "api_key=super-secret Bearer abc.def-123 password: hunter2"
        self.assertNotIn("super-secret", redact_secrets(text))
        self.assertNotIn("abc.def-123", redact_secrets(text))
        self.assertNotIn("hunter2", redact_secrets(text))

    def test_oracle_rag_is_safe_when_not_configured(self):
        with patch.dict(os.environ, {"ORACLE_USER": "", "ORACLE_PASSWORD": "", "ORACLE_DSN": ""}, clear=False):
            result = retrieve_from_oracle("ORA-00942: table or view does not exist")
        self.assertEqual(result.matches, [])
        self.assertEqual(result.status, "Oracle RAG not configured")

    def test_web_query_uses_error_signature_not_full_log(self):
        query = compact_search_query("ORA-00942 password=do-not-send java.lang.NullPointerException")
        self.assertIn("ORA-00942", query)
        self.assertIn("NullPointerException", query)
        self.assertNotIn("do-not-send", query)


if __name__ == "__main__":
    unittest.main()

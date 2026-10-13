"""Log analysis and optional OpenAI Responses API integration."""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from typing import Any


MAX_INPUT_CHARS = 30_000
OPENAI_MODEL = os.getenv("OPENAI_MODEL", "gpt-5.5")


@dataclass
class AnalysisResult:
    answer: str
    findings: list[dict[str, str]]
    mode: str
    input_lines: int


RULES = [
    (r"connection refused|connectexception", "Connection refused", "The target service is not accepting connections.", "Verify host and port, start the target service, and check firewall/network rules."),
    (r"timed? ?out|readtimeout|sockettimeout", "Timeout", "A network call or operation exceeded its configured wait time.", "Check downstream health and latency; then review timeout and retry settings."),
    (r"authentication failed|unauthorized|\b401\b|invalid token", "Authentication failure", "Credentials or access tokens were rejected.", "Validate the credential, expiry, scopes, and the configured authentication endpoint."),
    (r"forbidden|\b403\b|access denied", "Authorization failure", "The caller is authenticated but lacks permission.", "Review service roles, policy bindings, and resource-level permissions."),
    (r"not found|\b404\b", "Resource not found", "A requested endpoint, file, or resource could not be found.", "Check the URL/path, deployment version, and resource identifier."),
    (r"outofmemory|out of memory|memoryerror", "Memory exhaustion", "The process ran out of available memory.", "Inspect heap usage and leaks; increase memory only after identifying workload or retention causes."),
    (r"deadlock", "Database deadlock", "Concurrent transactions blocked each other.", "Retry the transaction safely and make transaction order/lock scope consistent."),
    (r"sql.*exception|psqlexception|integrity constraint", "Database error", "The application received a database exception.", "Check the full SQL error, schema constraints, connection health, and recent migrations."),
    (r"nullpointerexception|attributeerror|noneType", "Null reference", "Code used an object/value that was not initialized.", "Locate the first application stack-frame and validate inputs or add a guard condition."),
]


def redact_secrets(text: str) -> str:
    """Remove common credentials before text leaves the machine."""
    patterns = [
        r"(?i)(api[_-]?key|token|password|secret)\s*[:=]\s*[^\s,;]+",
        r"(?i)bearer\s+[a-z0-9._\-~+/=]+",
        r"AKIA[0-9A-Z]{16}",
    ]
    redacted = text
    for pattern in patterns:
        redacted = re.sub(pattern, "[REDACTED]", redacted)
    return redacted


def _rule_findings(text: str) -> list[dict[str, str]]:
    matches: list[dict[str, str]] = []
    lower = text.lower()
    for pattern, title, cause, fix in RULES:
        line_numbers = [
            str(index)
            for index, line in enumerate(lower.splitlines(), start=1)
            if re.search(pattern, line)
        ]
        if line_numbers:
            matches.append(
                {
                    "Signal": title,
                    "Line number(s)": ", ".join(line_numbers),
                    "Likely cause": cause,
                    "Recommended next step": fix,
                }
            )
    return matches


def _local_answer(findings: list[dict[str, str]]) -> str:
    if not findings:
        return (
            "### Summary\nNo recognised error signature was found.\n\n"
            "### Next steps\n1. Include 20–50 lines before and after the first `ERROR` or exception.\n"
            "2. Correlate the timestamp with deployment, configuration, and dependency changes.\n"
            "3. Enable `OPENAI_API_KEY` for a contextual AI analysis."
        )
    bullets = "\n".join(
        f"- **{item['Signal']}** (line {item['Line number(s)']}) — {item['Likely cause']}"
        for item in findings
    )
    fixes = "\n".join(f"{i + 1}. {item['Recommended next step']}" for i, item in enumerate(findings))
    return f"### What is likely wrong\n{bullets}\n\n### How to investigate and fix it\n{fixes}\n\n### Confidence\nRule-based match; confirm against the surrounding log context."


def _ai_answer(safe_text: str) -> str:
    from openai import OpenAI  # Imported only when the feature is configured.

    instructions = """You are a senior site reliability engineer. Analyze the supplied log excerpt.
Return concise Markdown with these headings: Summary, Evidence, Likely root cause,
Recommended fix, and Verification. Do not invent facts. State uncertainty clearly.
Do not ask the user to expose secrets, and never repeat any redacted value."""
    client = OpenAI()
    response = client.responses.create(
        model=OPENAI_MODEL,
        instructions=instructions,
        input=safe_text[:MAX_INPUT_CHARS],
    )
    return response.output_text


def analyze_log(log_text: str) -> AnalysisResult:
    """Analyze log text locally, using AI when a configured key is available."""
    trimmed = log_text[:MAX_INPUT_CHARS]
    findings = _rule_findings(trimmed)
    input_lines = len(log_text.splitlines())
    if not os.getenv("OPENAI_API_KEY"):
        return AnalysisResult(_local_answer(findings), findings, "Local rule-based", input_lines)
    try:
        return AnalysisResult(_ai_answer(redact_secrets(trimmed)), findings, "OpenAI AI-assisted", input_lines)
    except Exception as error:  # Preserve usability when an API request fails.
        answer = _local_answer(findings)
        answer += f"\n\n> AI analysis was unavailable ({type(error).__name__}); showing local diagnostics."
        return AnalysisResult(answer, findings, "Local fallback", input_lines)

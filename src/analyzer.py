"""Log analysis and optional OpenAI Responses API integration."""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from src.rag import KnowledgeMatch, RetrievalResult, format_knowledge, retrieve_from_oracle, retrieve_semantic_from_oracle
from src.web_research import search_web_when_needed


MAX_INPUT_CHARS = 30_000
OPENAI_MODEL = os.getenv("OPENAI_MODEL", "gpt-5.5")


@dataclass
class AnalysisResult:
    answer: str
    findings: list[dict[str, str]]
    mode: str
    input_lines: int
    rag_matches: list[KnowledgeMatch]
    web_sources: list[dict[str, str]]
    retrieval_status: str


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


def _rag_findings(log_text: str, matches: list[KnowledgeMatch]) -> list[dict[str, str]]:
    """Render evidence lines for runbooks retrieved from Oracle, not Python rules."""
    findings = []
    for match in matches:
        terms = [match.error_code, *match.match_terms.split("|")]
        line_numbers = [
            str(number) for number, line in enumerate(log_text.splitlines(), start=1)
            if any(term and term.lower() in line.lower() for term in terms)
        ]
        findings.append(
            {
                "Signal": match.title,
                "Line number(s)": ", ".join(dict.fromkeys(line_numbers)) or "Not present",
                "Likely cause": match.likely_causes,
                "Recommended next step": match.remediation,
            }
        )
    return findings


def _merge_retrievals(semantic: RetrievalResult, keyword: RetrievalResult, limit: int = 3) -> RetrievalResult:
    """Prioritise semantic matches and add deterministic matches without duplicates."""
    merged: list[KnowledgeMatch] = []
    seen = set()
    for match in [*semantic.matches, *keyword.matches]:
        identity = (match.technology, match.error_code)
        if identity not in seen:
            merged.append(match)
            seen.add(identity)
    if semantic.matches:
        status = semantic.status
    elif keyword.matches:
        status = keyword.status
    elif "unavailable" in semantic.status.lower():
        status = f"{semantic.status}; {keyword.status}"
    else:
        status = keyword.status
    return RetrievalResult(merged[:limit], status)


def _extract_specific_details(text: str) -> list[str]:
    """Extract facts that can be stated without guessing from common log formats."""
    details: list[str] = []

    # Oracle ORA-00001 only includes the constraint name; the table/columns must
    # be resolved from the database data dictionary unless the log includes SQL.
    for owner_and_constraint in re.findall(
        r"ORA-00001:\s*unique constraint\s*\(([^)]+)\)\s*violated", text, flags=re.IGNORECASE
    ):
        parts = owner_and_constraint.strip().split(".", maxsplit=1)
        if len(parts) == 2:
            owner, constraint = parts
            lookup = (
                "SELECT acc.table_name, acc.column_name, acc.position "
                "FROM all_cons_columns acc JOIN all_constraints ac "
                "ON ac.owner = acc.owner AND ac.constraint_name = acc.constraint_name "
                f"WHERE ac.owner = UPPER('{owner}') AND ac.constraint_name = UPPER('{constraint}') "
                "ORDER BY acc.position;"
            )
            details.append(
                f"Oracle constraint in the log: `{owner}.{constraint}`. The table and column(s) are **not present in this excerpt**; resolve them with: `{lookup}`"
            )
        else:
            details.append(f"Oracle constraint in the log: `{owner_and_constraint.strip()}`.")

    if re.search(r"ORA-00942:\s*table or view does not exist", text, flags=re.IGNORECASE):
        details.append(
            "Oracle error `ORA-00942` was detected. The missing table/view name is **not present in this error excerpt**; "
            "Oracle does not include it in this error message. Inspect the failing PL/SQL source line or SQL trace to identify it."
        )

    for procedure, line in re.findall(r'ORA-06512:\s*at\s*"([^"]+)"(?:,\s*line\s*(\d+))?', text, flags=re.IGNORECASE):
        location = f"`{procedure}`"
        if line:
            location += f", line **{line}**"
        details.append(f"Oracle call-stack location: {location}.")

        if "." in procedure and line:
            owner, object_name = procedure.split(".", maxsplit=1)
            source_lookup = (
                "SELECT line, text FROM all_source "
                f"WHERE owner = UPPER('{owner}') AND name = UPPER('{object_name}') "
                f"AND line BETWEEN {max(int(line) - 3, 1)} AND {int(line) + 3} ORDER BY line;"
            )
            details.append(
                f"To inspect the failing Oracle source context around `{procedure}` line **{line}**, run: `{source_lookup}`"
            )

    for constraint in re.findall(r'(?:constraint|UNIQUE KEY constraint)\s*["\']?([\w.$-]+)["\']?', text, flags=re.IGNORECASE):
        value = constraint.strip()
        if value and not any(value in item for item in details):
            details.append(f"Constraint name referenced in the log: `{value}`.")

    for columns, values in re.findall(r"Key\s*\(([^)]+)\)=\(([^)]+)\)", text, flags=re.IGNORECASE):
        details.append(f"Conflicting database key from the log: column(s) `{columns}`; value(s) `{values}`.")

    for table in re.findall(r"(?:relation|table|object)\s+[\"'`]([^\"'`]+)[\"'`]", text, flags=re.IGNORECASE):
        details.append(f"Database object referenced in the log: `{table}`.")

    for file_name, line, function in re.findall(r'File "([^"]+)", line (\d+), in ([^\n]+)', text):
        details.append(f"Python traceback location: `{file_name}`, line **{line}**, function `{function.strip()}`.")

    for class_name, file_name, line in re.findall(r"\bat\s+([\w.$]+)\(([^():]+):(\d+)\)", text):
        if not class_name.startswith(("java.", "javax.", "sun.")):
            details.append(f"Java stack-frame location: `{class_name}` in `{file_name}`, line **{line}**.")

    for method, file_name, line in re.findall(r"\bat\s+([\w.<>]+)\([^)]*\)\s+in\s+(.+?):line\s+(\d+)", text):
        details.append(f".NET stack-frame location: `{method}` in `{file_name}`, line **{line}**.")

    for function, file_name, line, column in re.findall(r"\bat\s+(.+?)\s*\(([^()]+):(\d+):(\d+)\)", text):
        if not file_name.endswith(".java"):
            details.append(f"JavaScript/Node stack-frame location: `{function.strip()}` in `{file_name}`, line **{line}**, column **{column}**.")

    for file_name, line in re.findall(r"\b([\w./\\-]+\.go):(\d+)", text):
        details.append(f"Go source location: `{file_name}`, line **{line}**.")

    # Keep the response readable when long traces contain many repeated frames.
    return list(dict.fromkeys(details))[:8]


def _detect_technologies(text: str) -> list[str]:
    """Identify the log format so the AI can apply the relevant evidence checklist."""
    checks = [
        (r"ora-\d+|oracle", "Oracle SQL/PLSQL"),
        (r"psqlexception|postgresql|sqlstate", "PostgreSQL"),
        (r"mysql|mariadb|duplicate entry", "MySQL/MariaDB"),
        (r"sqlserver|microsoft\.data\.sqlclient|invalid object name", "Microsoft SQL Server"),
        (r"\.java:\d+|java\.|springframework", "Java/JVM"),
        (r"traceback \(most recent call last\)|\.py\", line", "Python"),
        (r"node_modules|npm err|\.js:\d+:\d+|\.ts:\d+:\d+", "JavaScript/TypeScript/Node.js"),
        (r"system\.\w+exception|\.cs:line \d+", ".NET"),
        (r"panic:|\.go:\d+", "Go"),
        (r"http/\d\.\d|\b[1-5]\d\d\b", "HTTP/API"),
    ]
    lower = text.lower()
    return [technology for pattern, technology in checks if re.search(pattern, lower)] or ["Unclassified log format"]


def _supplemental_sources(rag_context: str, web_sources: list[dict[str, str]]) -> str:
    sections = []
    if rag_context:
        sections.append(f"### Oracle RAG knowledge-base guidance\n{rag_context}")
    if web_sources:
        links = "\n".join(f"- [{item['title']}]({item['url']})" for item in web_sources if item.get("url"))
        if links:
            sections.append(f"### Internet research (used only because Oracle RAG had no match)\n{links}")
    return "\n\n" + "\n\n".join(sections) if sections else ""


def _local_answer(
    findings: list[dict[str, str]], details: list[str], rag_context: str = "", web_sources: list[dict[str, str]] | None = None
) -> str:
    web_sources = web_sources or []
    if not findings:
        evidence = "\n".join(f"- {detail}" for detail in details) or "- No structured evidence could be extracted from this excerpt."
        answer = (
            "### Summary\nNo curated Oracle RAG runbook matched this log excerpt.\n\n"
            f"### Evidence captured from the log\n{evidence}\n\n"
            "### Next steps\n1. Include 20–50 lines before and after the first `ERROR` or exception.\n"
            "2. Correlate the timestamp with deployment, configuration, and dependency changes.\n"
            "3. Add a reviewed runbook and match terms to `ERROR_KNOWLEDGE`, or enable `OPENAI_API_KEY` for contextual AI analysis."
        )
        return answer + _supplemental_sources(rag_context, web_sources)
    bullets = "\n".join(
        f"- **{item['Signal']}** (line {item['Line number(s)']}) — {item['Likely cause']}"
        for item in findings
    )
    fixes = "\n".join(f"{i + 1}. {item['Recommended next step']}" for i, item in enumerate(findings))
    evidence = "\n".join(f"- {detail}" for detail in details) or "- No additional structured evidence could be extracted from this excerpt."
    answer = (
        f"### What is likely wrong\n{bullets}\n\n"
        f"### Evidence captured from the log\n{evidence}\n\n"
        f"### How to investigate and fix it\n{fixes}\n\n"
        "### Confidence\nCurated Oracle RAG match; confirm against the surrounding log context."
    )
    return answer + _supplemental_sources(rag_context, web_sources)


def _ai_answer(safe_text: str, details: list[str], rag_context: str, web_sources: list[dict[str, str]]) -> str:
    from openai import OpenAI  # Imported only when the feature is configured.

    extracted_evidence = "\n".join(f"- {detail}" for detail in details) or "- No structured details extracted."
    technologies = ", ".join(_detect_technologies(safe_text))
    instructions = f"""You are a senior site reliability engineer. Produce a detailed incident diagnosis
from the supplied log excerpt, not a generic error explanation. Return Markdown with these exact headings:
Summary, Detected technology, Exact evidence, Root-cause analysis, Targeted investigation, Recommended fix, and Verification.

Your response must be grounded strictly in the log. Extract and name, when present:
- the exact error code/type and its log line number;
- database owner/schema, constraint, table, column(s), duplicate key value(s), and SQL/procedure line;
- Java class, source file, and stack-frame line; or Python file, function, and traceback line.
Never invent a table, key, column, or root cause. If a requested detail is absent, write
"not present in the supplied log" and explain the precise safe command/query or extra log
needed to obtain it. For Oracle ORA-00001, the owner.constraint alone does not identify
the table/columns: include an ALL_CONS_COLUMNS/ALL_CONSTRAINTS lookup query. For Oracle
ORA-00942, explain that the missing object is not named in this exception and use each
ORA-06512 owner.package/trigger and line number to provide a focused ALL_SOURCE query for
the relevant source lines. Also state that a direct privilege granted to the runtime schema
may be needed for SQL in stored procedures (roles are not sufficient in definer-rights PL/SQL),
but label this as a verification step—not an established fact.

Detailed response contract:
- Quote every identifier and source line that is actually present.
- Separate confirmed facts from hypotheses.
- Include executable Oracle queries only when an Oracle error is present.
- Give ordered, concrete investigation steps tied to the reported source line(s).
- Do not give vague advice such as "check the database" or merely restate the Oracle Cause/Action text.
- For Java/JVM: identify the full exception chain, first application-owned stack frame, class, file and line.
- For Python: identify the final exception, traceback file/function/line, and the exact failing expression if shown.
- For JavaScript/Node/.NET/Go: identify the exception/panic, application stack frame, source file, line, and column if shown.
- For SQL engines: identify error code, database/schema, object, constraint, columns, values, query/procedure and line when shown.
- For HTTP/API errors: identify method, URL/path, status code, correlation/request ID, upstream service, and timeout duration when shown.
- For configuration/authentication errors: identify the exact missing/rejected setting, key name, endpoint, scope, or permission in the log, but never reveal secret values.
- Recommendations must map to the specific evidence. If only a generic exception is present, say exactly which additional context (for example, 20 preceding lines, the SQL statement, or the first application frame) is required.
Do not ask the user to expose secrets, and never repeat any redacted value.

Detected technology from log patterns: {technologies}

Structured evidence extracted before AI analysis:
{extracted_evidence}

Curated Oracle RAG context (use this as the primary remediation source when supplied):
{rag_context or '- No Oracle RAG match was found.'}

Internet research (only available after no Oracle RAG match):
{chr(10).join(f"- {item['title']}: {item['content']}" for item in web_sources) or '- No external research result was used.'}"""
    client = OpenAI()
    response = client.responses.create(
        model=OPENAI_MODEL,
        instructions=instructions,
        input=safe_text[:MAX_INPUT_CHARS],
    )
    return response.output_text


def _api_error_message(error: Exception) -> str:
    """Return safe, actionable API failure guidance without exposing credentials."""
    code = getattr(error, "code", None) or "unknown_code"
    status = getattr(error, "status_code", None) or "unknown status"
    guidance = {
        "credit_balance_exhausted": "API credits are exhausted. Add credits in the OpenAI API billing settings.",
        "project_spend_limit_exceeded": "This API project reached its hard spend limit. Raise the project's limit or wait for its reset.",
        "organization_spend_limit_exceeded": "The organization reached its hard spend limit. An organization owner must raise the limit or wait for its reset.",
        "organization_usage_limit_exceeded": "The organization reached its assigned usage limit. Review its usage limit or contact the organization owner.",
        "usage_limit_exceeded": "A billing or usage limit was reached. Check the project's credits and spend limits.",
        "rate_limit_exceeded": "Requests are arriving too quickly. Wait briefly and retry; reduce repeated clicks or large parallel requests.",
        "slow_down": "Requests increased too quickly. Wait before retrying and submit requests more gradually.",
    }.get(str(code), "Check OpenAI API billing, credits, project spend limits, and request-rate limits.")
    return f"> AI analysis was unavailable (HTTP {status}, `{code}`). {guidance} Showing local diagnostics."


def analyze_log(log_text: str) -> AnalysisResult:
    """Analyze log text locally, using AI when a configured key is available."""
    trimmed = log_text[:MAX_INPUT_CHARS]
    details = _extract_specific_details(trimmed)
    input_lines = len(log_text.splitlines())
    semantic_retrieval = retrieve_semantic_from_oracle(trimmed)
    keyword_retrieval = retrieve_from_oracle(trimmed)
    retrieval = _merge_retrievals(semantic_retrieval, keyword_retrieval)
    findings = _rag_findings(trimmed, retrieval.matches)
    rag_context = format_knowledge(retrieval.matches)
    web_sources = search_web_when_needed(trimmed, bool(retrieval.matches))
    if not os.getenv("OPENAI_API_KEY"):
        mode = "Oracle Vector RAG + local diagnostics" if semantic_retrieval.matches else (
            "Oracle RAG + local diagnostics" if retrieval.matches else "No RAG match + local diagnostics"
        )
        return AnalysisResult(
            _local_answer(findings, details, rag_context, web_sources),
            findings,
            mode,
            input_lines,
            retrieval.matches,
            web_sources,
            retrieval.status,
        )
    try:
        mode = "Oracle Vector RAG + OpenAI AI-assisted" if semantic_retrieval.matches else (
            "Oracle RAG + OpenAI AI-assisted" if retrieval.matches else "OpenAI AI-assisted"
        )
        return AnalysisResult(
            _ai_answer(redact_secrets(trimmed), details, rag_context, web_sources),
            findings,
            mode,
            input_lines,
            retrieval.matches,
            web_sources,
            retrieval.status,
        )
    except Exception as error:  # Preserve usability when an API request fails.
        answer = _local_answer(findings, details, rag_context, web_sources)
        answer += "\n\n" + _api_error_message(error)
        return AnalysisResult(
            answer,
            findings,
            "Local fallback",
            input_lines,
            retrieval.matches,
            web_sources,
            retrieval.status,
        )

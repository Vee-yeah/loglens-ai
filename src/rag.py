"""Oracle-backed retrieval layer for curated error-resolution knowledge."""

from __future__ import annotations

import os
import re
import logging
from pathlib import Path
from time import perf_counter
from dataclasses import dataclass


LOGGER = logging.getLogger("loglens.rag")
if not LOGGER.handlers:
    handler = logging.FileHandler(Path(__file__).resolve().parents[1] / "loglens.log", encoding="utf-8")
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
    LOGGER.addHandler(handler)
    LOGGER.setLevel(logging.INFO)
    LOGGER.propagate = False


@dataclass(frozen=True)
class KnowledgeMatch:
    technology: str
    error_code: str
    title: str
    description: str
    likely_causes: str
    remediation: str
    verification: str
    source_url: str | None
    match_terms: str
    score: int


@dataclass(frozen=True)
class RetrievalResult:
    matches: list[KnowledgeMatch]
    status: str


def _is_configured() -> bool:
    return all(os.getenv(name) for name in ("ORACLE_USER", "ORACLE_PASSWORD", "ORACLE_DSN"))


def _is_vector_configured() -> bool:
    return all(os.getenv(name) for name in ("ORACLE_VECTOR_USER", "ORACLE_VECTOR_PASSWORD", "ORACLE_DSN"))


def _connection_options(user: str, password: str, dsn: str) -> dict[str, object]:
    raw_dsn = dsn.strip()
    # Wallet-derived Easy Connect query parameters can force TLS even after the
    # host and service have been changed to the local Docker database.  A local
    # LogLens database is always direct TCP, so retain only host:port/service.
    local_dsn = re.sub(r"^(?:tcp|tcps)://", "", raw_dsn, flags=re.IGNORECASE).split("?", 1)[0]
    is_local_dsn = bool(
        re.match(r"^(?:localhost|127\.0\.0\.1|::1)(?::\d+)?(?:/|$)", local_dsn, re.IGNORECASE)
    )
    options: dict[str, object] = {
        "user": user, "password": password, "dsn": local_dsn if is_local_dsn else raw_dsn,
        "tcp_connect_timeout": float(os.getenv("ORACLE_CONNECT_TIMEOUT_SECONDS", "8")),
    }
    # A local Docker database uses direct TCP (for example localhost:1521/myatp).
    # Do not let a previously configured Autonomous Database wallet force TLS
    # onto that local listener.
    if is_local_dsn:
        LOGGER.info("Oracle local TCP target %s; wallet settings are ignored", local_dsn)
        return options

    if os.getenv("ORACLE_CONFIG_DIR"):
        options["config_dir"] = os.environ["ORACLE_CONFIG_DIR"]
    if os.getenv("ORACLE_WALLET_LOCATION"):
        options["wallet_location"] = os.environ["ORACLE_WALLET_LOCATION"]
    if os.getenv("ORACLE_WALLET_PASSWORD"):
        options["wallet_password"] = os.environ["ORACLE_WALLET_PASSWORD"]
    return options


def _as_text(value: object | None) -> str:
    """Convert Oracle CLOB/LOB values to ordinary text for matching and display."""
    if value is None:
        return ""
    return value.read() if hasattr(value, "read") else str(value)


def _score_record(log_text: str, error_code: str, match_terms: str) -> int:
    """Rank exact error codes above curated terms; no model or key is required."""
    normalized_log = log_text.upper()
    score = 0
    if error_code and error_code.upper() in normalized_log:
        score += 100
    for term in (item.strip() for item in _as_text(match_terms).split("|")):
        if term and term.upper() in normalized_log:
            score += 10 + min(len(term), 20)
    return score


def _safe_error_detail(error: Exception) -> str:
    """Keep diagnostics useful without allowing a configured password into logs."""
    detail = str(error)
    password = os.getenv("ORACLE_PASSWORD")
    if password:
        detail = detail.replace(password, "[REDACTED]")
    return detail.replace("\n", " ")[:500]


def retrieve_from_oracle(log_text: str, limit: int = 3) -> RetrievalResult:
    """Retrieve approved runbooks from Oracle before any external research.

    The database connection is intentionally optional: the app remains runnable for
    demonstrations without credentials, while production deployments set the three
    ORACLE_* environment variables.
    """
    if not _is_configured():
        LOGGER.info("Oracle RAG skipped: connection settings are not configured")
        return RetrievalResult([], "Oracle RAG not configured")

    try:
        import oracledb
    except ImportError:
        LOGGER.warning("Oracle RAG skipped: python-oracledb is not installed")
        return RetrievalResult([], "Oracle RAG driver is not installed")

    try:
        started_at = perf_counter()
        with oracledb.connect(**_connection_options(
            os.environ["ORACLE_USER"], os.environ["ORACLE_PASSWORD"], os.environ["ORACLE_DSN"]
        )) as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    """
                    SELECT technology, error_code, title, description, likely_causes,
                           remediation, verification, source_url, match_terms
                    FROM error_knowledge
                    WHERE is_active = 'Y'
                    """
                )
                ranked = []
                for row in cursor:
                    score = _score_record(log_text, _as_text(row[1]), row[8])
                    if score:
                        ranked.append(
                            KnowledgeMatch(
                                technology=_as_text(row[0]), error_code=_as_text(row[1]), title=_as_text(row[2]),
                                description=_as_text(row[3]), likely_causes=_as_text(row[4]), remediation=_as_text(row[5]),
                                verification=_as_text(row[6]), source_url=_as_text(row[7]) or None,
                                match_terms=_as_text(row[8]), score=score,
                            )
                        )
        ranked.sort(key=lambda item: item.score, reverse=True)
        matches = ranked[:limit]
        elapsed = perf_counter() - started_at
        LOGGER.info("Oracle RAG lookup succeeded: %s match(es) in %.2fs", len(matches), elapsed)
        return RetrievalResult(matches, f"Oracle RAG ({len(matches)} match(es), {elapsed:.1f}s)")
    except Exception as error:
        # The message is intentionally short because connection strings can be sensitive.
        LOGGER.warning("Oracle RAG lookup failed: %s: %s", type(error).__name__, _safe_error_detail(error))
        return RetrievalResult([], f"Oracle RAG unavailable ({type(error).__name__})")


def retrieve_semantic_from_oracle(log_text: str, limit: int = 3) -> RetrievalResult:
    """Retrieve semantically related runbooks with the local Oracle model."""
    if not _is_vector_configured():
        return RetrievalResult([], "Oracle Vector RAG not configured")
    try:
        import oracledb
    except ImportError:
        return RetrievalResult([], "Oracle Vector RAG driver is not installed")

    safe_limit = max(1, min(int(limit), 10))
    model = os.getenv("ORACLE_VECTOR_MODEL", "ALL_MINILM_L12_V2")
    query = f"""
        WITH query_embedding AS (
          SELECT DBMS_VECTOR_CHAIN.UTL_TO_EMBEDDING(
            :log_text, JSON(:embedding_params)
          ) AS vector_value FROM dual
        )
        SELECT technology, error_code, title, description, likely_causes,
               remediation, verification, source_url, match_terms,
               ROUND((1 - VECTOR_DISTANCE(embedding, vector_value, COSINE)) * 100) AS semantic_score
        FROM error_runbook_vectors CROSS JOIN query_embedding
        ORDER BY VECTOR_DISTANCE(embedding, vector_value, COSINE)
        FETCH FIRST {safe_limit} ROWS ONLY
    """
    try:
        started_at = perf_counter()
        with oracledb.connect(**_connection_options(
            os.environ["ORACLE_VECTOR_USER"], os.environ["ORACLE_VECTOR_PASSWORD"], os.environ["ORACLE_DSN"]
        )) as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    query,
                    log_text=log_text[:30_000],
                    embedding_params=f'{{"provider":"database", "model":"{model}"}}',
                )
                matches = [
                    KnowledgeMatch(
                        technology=_as_text(row[0]), error_code=_as_text(row[1]), title=_as_text(row[2]),
                        description=_as_text(row[3]), likely_causes=_as_text(row[4]), remediation=_as_text(row[5]),
                        verification=_as_text(row[6]), source_url=_as_text(row[7]) or None,
                        match_terms=_as_text(row[8]), score=int(row[9]),
                    )
                    for row in cursor
                ]
        elapsed = perf_counter() - started_at
        LOGGER.info("Oracle Vector RAG lookup succeeded: %s match(es) in %.2fs", len(matches), elapsed)
        return RetrievalResult(matches, f"Oracle Vector RAG ({len(matches)} match(es), {elapsed:.1f}s)")
    except Exception as error:
        LOGGER.warning("Oracle Vector RAG lookup failed: %s: %s", type(error).__name__, _safe_error_detail(error))
        return RetrievalResult([], f"Oracle Vector RAG unavailable ({type(error).__name__})")


def format_knowledge(matches: list[KnowledgeMatch]) -> str:
    """Render retrieved records as grounded context for local or AI analysis."""
    blocks = []
    for item in matches:
        blocks.append(
            f"### {item.technology}: {item.error_code} — {item.title}\n"
            f"**Description:** {item.description}\n\n"
            f"**Likely causes:** {item.likely_causes}\n\n"
            f"**Approved remediation:** {item.remediation}\n\n"
            f"**Verification:** {item.verification}"
        )
    return "\n\n".join(blocks)


def compact_search_query(log_text: str) -> str:
    """Create a privacy-minimised web query: codes/types only, never raw log text."""
    candidates = re.findall(r"\b(?:ORA-\d{5}|HTTP\s*\d{3}|[A-Za-z_]+(?:Exception|Error))\b", log_text)
    return " ".join(dict.fromkeys(candidates))[:300]

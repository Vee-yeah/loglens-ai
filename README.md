# LogLens AI

LogLens AI is a Streamlit application built around Oracle AI Vector RAG. It turns raw log files, stack traces, and pasted error messages into a semantic search of reviewed Oracle runbooks, then provides a concise diagnosis and investigation path.

## Vector RAG: primary capability

LogLens uses retrieval before optional generative AI:

    Log / pasted error -> local evidence -> Oracle Vector RAG -> exact Oracle RAG -> local or optional AI diagnosis

Oracle AI Vector Search uses the in-database ALL_MINILM_L12_V2 embedding model to retrieve related runbooks even when the input wording does not exactly match stored error text. For example, a request that a customer cannot see current account money retrieves banking balance and account runbooks.

## Features

- **Oracle AI Vector RAG first:** semantic similarity search over reviewed Oracle runbooks.
- **Exact Oracle RAG fallback:** error-code and phrase matching over ERROR_KNOWLEDGE.
- Upload `.log` or `.txt` files.
- Paste an exception, stack trace, or error excerpt.
- Detect common Java, Python, and SQL/database failure patterns locally, including timeouts, missing dependencies, null values, data-constraint failures, and memory errors.
- Optionally use the OpenAI Responses API for contextual root-cause analysis and remediation steps after retrieval.
- Apply a first-layer privacy filter before an AI request: credentials, account numbers, email addresses, phone numbers, Social Security numbers, and IBANs are masked. Input is capped at 30,000 characters.
- Continue to work in local rule-based mode when no API key is configured.
- Use optional web research only when Oracle RAG has no match; the raw log is not sent to web search.

## Technology

- Front end: Streamlit
- Back end: Python
- Optional AI: OpenAI Python SDK / Responses API
- Optional RAG database: Oracle Database

## Run locally

Prerequisite: Python 3.10 or later.

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
streamlit run app.py
```

Open the local address shown by Streamlit, usually `http://localhost:8501`.

## Enable AI analysis (optional)

The app works without an API key using local rules. To enable AI-assisted analysis, set an environment variable before running the app:

```powershell
$env:OPENAI_API_KEY="your_api_key"
# Optional: override the model configured in src/analyzer.py
$env:OPENAI_MODEL="gpt-5.5"
streamlit run app.py
```

The official SDK reads `OPENAI_API_KEY` from the environment; do not put keys in source code or commit a `.env` file. See the [OpenAI Python SDK reference](https://developers.openai.com/api/reference/python) for setup details.

## Project structure

```text
app.py              Streamlit user interface
src/analyzer.py     Rule engine, secret redaction, and optional AI integration
requirements.txt    Python dependencies
sample_logs/        Java, SQL, Python, and mixed-error test inputs
README.md           Setup and project overview
README.txt          Concise submission-ready overview
RELEASE_NOTES.md    Version history
VERSION             Current release number
database/           Oracle schema and seeded error-knowledge runbooks
```

## Exact Oracle RAG knowledge base

The app queries Oracle first for curated error runbooks. If Oracle returns no match, optional internet research is attempted only when `TAVILY_API_KEY` is configured. The raw log is never sent to web search; only a compact error signature is used.

1. Provision an Oracle database/schema (for example, Oracle Free, XE, or an organisation-managed Oracle instance).
2. Run [database/01_create_error_knowledge.sql](database/01_create_error_knowledge.sql), [database/02_seed_error_knowledge.sql](database/02_seed_error_knowledge.sql), [database/03_seed_common_runbooks.sql](database/03_seed_common_runbooks.sql), then [database/04_seed_banking_functional_runbooks.sql](database/04_seed_banking_functional_runbooks.sql).
3. Set `ORACLE_USER`, `ORACLE_PASSWORD`, and `ORACLE_DSN` as environment variables.
4. Reinstall dependencies: `pip install -r requirements.txt`.

The seed migrations contain Oracle, Java, Python, SQL, HTTP, network, and platform runbooks. Add reviewed organisation-specific errors to `ERROR_KNOWLEDGE`; the application ranks exact error codes above matching phrases. The application contains no embedded error-rule catalogue: curated Oracle records are the source of diagnostic matches.

`04_seed_banking_functional_runbooks.sql` adds fictional banking examples (accounts, payments, limits, KYC, ledger, FX, loans, and cards). Its schema, table, service, and queue names are intentionally illustrative: replace them with approved internal names and processes before any production use.

## Oracle AI Vector Search setup

After loading the local Oracle model `ALL_MINILM_L12_V2` for `LOGLENS_VECTOR`, run [database/05_create_vector_rag.sql](database/05_create_vector_rag.sql) as that user. The app then embeds each input locally in Oracle and retrieves semantically related runbooks before exact phrase matching. Set `ORACLE_VECTOR_USER`, `ORACLE_VECTOR_PASSWORD`, and `ORACLE_VECTOR_MODEL` in addition to the normal Oracle wallet settings.

For this small demonstration knowledge base, exact similarity search is used if a local HNSW index cannot be created because of database shared-memory limits. This remains true vector retrieval; a vector index is a performance optimization for larger collections.

## Security and limitations

- Review logs before analysis. Do not upload customer data, credentials, or other sensitive production information.
- Redaction covers common patterns, but is not a guarantee that all sensitive data is removed.
- AI output is diagnostic guidance, not a production change instruction. Verify recommendations in your environment.
- Large logs are truncated to the first 30,000 characters; provide a focused error window for best results.

## Submission checklist

1. Create a GitHub repository and upload these files, or zip this project folder to OneDrive.
2. Add screenshots of both the upload and paste workflows to your certification submission.
3. Include the release notes and explain the local fallback mode during the demonstration.

## Version

Current release: **v1.0.0** (13 October 2026).

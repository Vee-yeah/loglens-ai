# LogLens AI

LogLens AI is a Streamlit application that turns raw log files, stack traces, and pasted error messages into a concise explanation of what failed and how to investigate it. It demonstrates a common engineering workflow: reducing time-to-diagnosis during incidents.

## Features

- Upload `.log` or `.txt` files.
- Paste an exception, stack trace, or error excerpt.
- Detect common Java, Python, and SQL/database failure patterns locally, including timeouts, missing dependencies, null values, data-constraint failures, and memory errors.
- Optionally use the OpenAI Responses API for contextual root-cause analysis and remediation steps.
- Redact common secrets before an AI request and cap input at 30,000 characters.
- Continue to work in local rule-based mode when no API key is configured.

## Technology

- Front end: Streamlit
- Back end: Python
- Optional AI: OpenAI Python SDK / Responses API

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
```

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

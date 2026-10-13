LOGLENS AI — v1.0.0

Purpose
-------
LogLens AI is an engineering troubleshooting tool. It analyzes uploaded log files
or pasted stack traces and explains what likely failed, why, and what to check next.

Key features
------------
1. Upload .log or .txt files through a Streamlit web UI.
2. Paste an error message or stack trace directly into the UI.
3. Detect common incidents locally: connection failures, timeouts, authentication,
   authorization, missing resources, database failures, memory exhaustion, and nulls.
4. Optionally send redacted, size-limited log text to the OpenAI Responses API for
   deeper contextual analysis.
5. Keep working in local mode if an API key is not configured or AI is unavailable.

Quick start
-----------
1. Install Python 3.10 or later.
2. Run: pip install -r requirements.txt
3. Run: streamlit run app.py
4. Open the URL displayed in the terminal.

Optional AI setup
-----------------
Set OPENAI_API_KEY as an environment variable before starting the app.
Never commit the key or a .env file. See README.md for complete setup, security
notes, architecture, and submission instructions.

Project files
-------------
app.py             Streamlit interface
src/analyzer.py    Analysis engine, redaction, and optional AI integration
sample.log         Demonstration input
sample_logs/       Java, SQL, Python, and mixed-error test inputs
README.md          Full documentation
RELEASE_NOTES.md   Version history
VERSION            Current release version

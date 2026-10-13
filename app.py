"""Streamlit entry point for LogLens AI."""

from __future__ import annotations

import os

import streamlit as st

from src.analyzer import AnalysisResult, analyze_log


st.set_page_config(page_title="LogLens AI", page_icon="🔎", layout="wide")


def render_result(result: AnalysisResult) -> None:
    st.subheader("Analysis")
    st.caption(f"Mode: {result.mode} · Input: {result.input_lines} lines")
    st.markdown(result.answer)
    if result.findings:
        st.subheader("Detected signals")
        st.dataframe(result.findings, use_container_width=True, hide_index=True)


def main() -> None:
    st.title("🔎 LogLens AI")
    st.write("Turn application logs and error messages into an actionable diagnosis.")
    if os.getenv("OPENAI_API_KEY"):
        st.success("AI-assisted analysis is enabled. Detailed analysis will use the configured OpenAI API key.")
    else:
        st.warning(
            "Local rule-based mode is active — no `OPENAI_API_KEY` was found in this Streamlit process. "
            "Start Streamlit from the same PowerShell window where you set the key to enable detailed AI analysis."
        )

    tab_upload, tab_paste = st.tabs(["Upload a log", "Paste an error"])
    with tab_upload:
        file = st.file_uploader("Choose a .log or .txt file", type=["log", "txt"])
        if file:
            log_text = file.getvalue().decode("utf-8", errors="replace")
            st.caption(f"Loaded **{file.name}** ({len(log_text):,} characters).")
            if st.button("Analyze uploaded log", type="primary"):
                with st.spinner("Analyzing log safely..."):
                    render_result(analyze_log(log_text))

    with tab_paste:
        pasted_text = st.text_area(
            "Paste an error message, stack trace, or log excerpt",
            height=260,
            placeholder="Example: java.net.ConnectException: Connection refused",
        )
        if st.button("Analyze pasted text", type="primary"):
            if not pasted_text.strip():
                st.warning("Paste an error or log excerpt first.")
            else:
                with st.spinner("Analyzing error..."):
                    render_result(analyze_log(pasted_text))

    with st.expander("Privacy and safe use"):
        st.write(
            "LogLens redacts common credentials before an AI request. Review logs before "
            "uploading: avoid sending personal data, production secrets, or customer data."
        )


if __name__ == "__main__":
    main()

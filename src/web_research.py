"""Optional internet research used only after Oracle RAG has no match."""

from __future__ import annotations

import os

import requests

from src.rag import compact_search_query


def search_web_when_needed(log_text: str, has_rag_match: bool) -> list[dict[str, str]]:
    """Search approved public sources via Tavily only when explicitly configured.

    A compact error signature—not the raw log—is sent to protect log privacy.
    """
    api_key = os.getenv("TAVILY_API_KEY")
    if has_rag_match or not api_key:
        return []
    query = compact_search_query(log_text)
    if not query:
        return []
    try:
        response = requests.post(
            "https://api.tavily.com/search",
            json={"api_key": api_key, "query": query, "max_results": 3, "search_depth": "basic"},
            timeout=10,
        )
        response.raise_for_status()
        return [
            {"title": item.get("title", "Untitled"), "url": item.get("url", ""), "content": item.get("content", "")[:700]}
            for item in response.json().get("results", [])
        ]
    except requests.RequestException:
        return []

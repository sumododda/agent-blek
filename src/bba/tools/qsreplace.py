"""Query string parameter replacement — pure Python, no external dependency."""
from __future__ import annotations

from urllib.parse import urlparse, parse_qs, urlencode, urlunparse


class QsreplaceTool:
    """Replace all query string parameter values with a given payload.

    Pure Python implementation — no subprocess, no shell, no external binary.
    """

    def replace(self, url: str, payload: str) -> str | None:
        """Replace all query param values in url with payload. Returns None if no params."""
        parsed = urlparse(url)
        if not parsed.query:
            return None
        params = parse_qs(parsed.query, keep_blank_values=True)
        replaced = {k: [payload] for k in params}
        new_query = urlencode(replaced, doseq=True)
        return urlunparse(parsed._replace(query=new_query))

    def batch_replace(self, urls: list[str], payload: str) -> list[str]:
        """Replace params in all URLs, deduplicate results."""
        seen: set[str] = set()
        results: list[str] = []
        for url in urls:
            replaced = self.replace(url, payload)
            if replaced and replaced not in seen:
                seen.add(replaced)
                results.append(replaced)
        return results

from __future__ import annotations

import re


_INJECTION_PATTERNS = [
    re.compile(r"ignore\s+(all\s+)?previous\s+instructions", re.I),
    re.compile(r"ignore\s+(all\s+)?prior\s+instructions", re.I),
    re.compile(r"disregard\s+(all\s+)?previous", re.I),
    re.compile(r"reveal\s+(your\s+)?system\s+prompt", re.I),
    re.compile(r"you\s+are\s+now\s+a\s+", re.I),
    re.compile(r"<system>.*?</system>", re.I | re.S),
    re.compile(r"<\s*(?:assistant|user|human)\s*>", re.I),
    re.compile(r"override\s+(?:all\s+)?instructions", re.I),
    re.compile(r"new\s+system\s+prompt", re.I),
]

_HTML_COMMENT = re.compile(r"<!--.*?-->", re.S)
_SCRIPT_TAG = re.compile(r"<script[^>]*>.*?</script>", re.I | re.S)
_STYLE_HIDDEN = re.compile(
    r"<[^>]+style\s*=\s*[\"'][^\"']*(?:display\s*:\s*none|visibility\s*:\s*hidden)[^\"']*[\"'][^>]*>.*?</[^>]+>",
    re.I | re.S,
)
_META_TAG = re.compile(r"<meta[^>]*>", re.I)


class Sanitizer:
    def sanitize_html(self, text: str) -> str:
        text = _HTML_COMMENT.sub("", text)
        text = _SCRIPT_TAG.sub("", text)
        text = _STYLE_HIDDEN.sub("", text)
        text = _META_TAG.sub("", text)
        return text

    def has_injection_markers(self, text: str) -> bool:
        return any(p.search(text) for p in _INJECTION_PATTERNS)

    def sanitize_headers(self, headers: dict[str, str]) -> dict[str, str]:
        cleaned = {}
        for key, value in headers.items():
            if self.has_injection_markers(value):
                cleaned[key] = "[REDACTED: potential injection]"
            else:
                cleaned[key] = value
        return cleaned

    def sanitize(self, text: str, max_length: int = 100_000) -> str:
        text = self.sanitize_html(text)
        if len(text) > max_length:
            text = text[:max_length] + "\n[TRUNCATED]"
        return text

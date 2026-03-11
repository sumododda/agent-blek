"""GF-like pattern matching for URL classification.

Applies regex patterns to URLs to identify potential vulnerability candidates.
Based on tomnomnom's gf patterns: aws-keys, urls, ssrf, xss, sqli, redirect, etc.
"""
from __future__ import annotations

import re
from bba.db import Database
from bba.tool_runner import ToolRunner

PATTERNS = {
    "xss": re.compile(
        r"[?&](q|search|query|keyword|term|input|text|value|data|content|body|message|comment|name|title|desc|url|redirect|return|callback|next|ref|page|view|action|func|cmd|exec|ping|id)=",
        re.IGNORECASE,
    ),
    "sqli": re.compile(
        r"[?&](id|user|account|number|order|no|select|report|role|update|query|search|results|category|type|sort|field|column|table|from|to|row|process|limit|page|dir|where|key|format|date)=",
        re.IGNORECASE,
    ),
    "ssrf": re.compile(
        r"[?&](url|uri|path|dest|redirect|uri|src|source|host|link|domain|site|feed|proxy|return|next|target|rurl|open|nav|go|fetch|load|request|file|document|folder|pg|style|img|doc|remote|callback)=",
        re.IGNORECASE,
    ),
    "redirect": re.compile(
        r"[?&](url|redirect|redir|return|next|dest|destination|rurl|out|view|target|to|goto|link|linkurl|go|forward|continue|returnUrl|returnTo|checkout_url|login_url)=",
        re.IGNORECASE,
    ),
    "lfi": re.compile(
        r"[?&](file|document|folder|root|path|pg|style|pdf|template|php_path|doc|page|name|cat|dir|action|board|date|detail|download|prefix|include|inc|locate|show|site|type|view|content|layout|mod|conf|log)=",
        re.IGNORECASE,
    ),
    "rce": re.compile(
        r"[?&](cmd|exec|command|execute|ping|query|jump|code|reg|do|func|arg|option|load|process|step|read|function|req|feature|exe|module|payload|run|print|daemon|upload|log|ip|cli|die)=",
        re.IGNORECASE,
    ),
    "idor": re.compile(
        r"[?&](id|user|account|number|order|no|doc|key|email|group|profile|edit|report)=\d+",
        re.IGNORECASE,
    ),
    "interesting-ext": re.compile(
        r"\.(sql|bak|old|backup|zip|tar\.gz|tgz|rar|7z|log|conf|config|env|ini|xml|json|yml|yaml|db|sqlite|dump|csv)(\?|$)",
        re.IGNORECASE,
    ),
    "ssti": re.compile(
        r"[?&](template|render|preview|theme|view|layout|content|page|name|msg|text|body|title|desc|comment|input|field|data|value|expression|eval|output|display|format|engine|tpl|snippet)=",
        re.IGNORECASE,
    ),
    "cmdi": re.compile(
        r"[?&](cmd|exec|command|execute|ping|query|jump|code|reg|do|func|arg|option|load|process|step|read|function|req|feature|exe|module|payload|run|print|daemon|upload|log|ip|cli|dir|address|host|port|timeout)=",
        re.IGNORECASE,
    ),
    "crlf": re.compile(
        r"[?&](url|redirect|redir|return|next|dest|destination|rurl|out|view|target|to|goto|link|forward|continue|returnUrl|returnTo|location|locale|lang|origin|callback|path)=",
        re.IGNORECASE,
    ),
    "cors": re.compile(
        r"[?&](callback|jsonp|cb|json_callback|jsonpcallback|_callback|api_callback|endpoint|origin)=",
        re.IGNORECASE,
    ),
    "jwt": re.compile(
        r"[?&](token|jwt|auth_token|access_token|id_token|session_token|bearer|authorization)=",
        re.IGNORECASE,
    ),
    "xxe": re.compile(
        r"[?&](xml|xmldata|soap|wsdl|content|data|payload|body|file|document|feed|rss|import|export|upload)=",
        re.IGNORECASE,
    ),
    "prototype-pollution": re.compile(
        r"[?&](__proto__|constructor|prototype)[\[.=]",
        re.IGNORECASE,
    ),
    "upload": re.compile(
        r"[?&](file|upload|attachment|document|image|img|photo|avatar|media|import)=",
        re.IGNORECASE,
    ),
}


class GfPatternsTool:
    """Classify URLs by vulnerability pattern for targeted scanning."""

    def __init__(self, runner: ToolRunner, db: Database, program: str):
        self.runner = runner
        self.db = db
        self.program = program

    def classify_urls(self, urls: list[str]) -> dict[str, list[str]]:
        """Classify a list of URLs by matching vulnerability patterns."""
        classified: dict[str, list[str]] = {name: [] for name in PATTERNS}
        for url in urls:
            for name, pattern in PATTERNS.items():
                if pattern.search(url):
                    classified[name].append(url)
        return classified

    async def run(self, urls: list[str]) -> dict:
        """Classify URLs and return grouped results for targeted scanning."""
        classified = self.classify_urls(urls)
        summary = {name: len(matches) for name, matches in classified.items() if matches}
        total = sum(summary.values())

        await self.db.log_action(
            "gf_pattern_match", "gf-patterns", f"{len(urls)} urls",
            f"Classified {total} URLs: {summary}",
        )

        return {
            "total_classified": total,
            "total_urls": len(urls),
            "summary": summary,
            "classified": {k: v for k, v in classified.items() if v},
        }

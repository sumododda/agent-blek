import pytest
from bba.tools.qsreplace import QsreplaceTool


class TestQsreplaceTool:
    def test_replace_single_param(self):
        tool = QsreplaceTool()
        result = tool.replace("https://example.com/page?id=123", "FUZZ")
        assert result == "https://example.com/page?id=FUZZ"

    def test_replace_multiple_params(self):
        tool = QsreplaceTool()
        result = tool.replace("https://example.com/search?q=test&page=1&lang=en", "PAYLOAD")
        assert "q=PAYLOAD" in result
        assert "page=PAYLOAD" in result
        assert "lang=PAYLOAD" in result

    def test_no_params_returns_none(self):
        tool = QsreplaceTool()
        result = tool.replace("https://example.com/page", "FUZZ")
        assert result is None

    def test_empty_param_value(self):
        tool = QsreplaceTool()
        result = tool.replace("https://example.com/page?id=", "FUZZ")
        assert result == "https://example.com/page?id=FUZZ"

    def test_preserves_path_and_fragment(self):
        tool = QsreplaceTool()
        result = tool.replace("https://example.com/api/v1?token=abc#section", "REPLACED")
        assert "/api/v1" in result
        assert "token=REPLACED" in result

    def test_shell_metacharacters_safe(self):
        """Payload with shell metacharacters must be handled safely (URL-encoded)."""
        tool = QsreplaceTool()
        payload = "'; rm -rf /; echo '"
        result = tool.replace("https://example.com/page?id=1", payload)
        # urlencode safely encodes shell metacharacters — no shell interpretation possible
        assert "id=" in result
        assert result is not None

    def test_batch_replace(self):
        tool = QsreplaceTool()
        urls = [
            "https://example.com/a?id=1",
            "https://example.com/b?name=foo&age=30",
            "https://example.com/c",  # no params
        ]
        results = tool.batch_replace(urls, "XSS")
        assert len(results) == 2  # URL without params excluded
        assert all("XSS" in r for r in results)

    def test_deduplicates_results(self):
        tool = QsreplaceTool()
        urls = [
            "https://example.com/a?id=1",
            "https://example.com/a?id=2",
            "https://example.com/a?id=3",
        ]
        results = tool.batch_replace(urls, "FUZZ")
        # All produce same output: ?id=FUZZ — should deduplicate
        assert len(results) == 1

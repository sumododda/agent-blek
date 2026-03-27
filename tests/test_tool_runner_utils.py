import json
import pytest
from pathlib import Path
from bba.tool_runner import ToolRunner


class TestParseJsonl:
    def test_parses_valid_jsonl(self):
        output = '{"host":"a.com"}\n{"host":"b.com"}\n'
        results = ToolRunner.parse_jsonl(output)
        assert len(results) == 2
        assert results[0]["host"] == "a.com"

    def test_skips_invalid_lines(self):
        output = '{"host":"a.com"}\nnot-json\n{"host":"b.com"}\n'
        results = ToolRunner.parse_jsonl(output)
        assert len(results) == 2

    def test_handles_empty_output(self):
        assert ToolRunner.parse_jsonl("") == []
        assert ToolRunner.parse_jsonl("  \n  \n") == []

    def test_handles_blank_lines(self):
        output = '{"a":1}\n\n\n{"b":2}\n'
        results = ToolRunner.parse_jsonl(output)
        assert len(results) == 2


class TestCreateInputFile:
    def test_creates_file_with_targets(self, tmp_path):
        targets = ["a.example.com", "b.example.com"]
        result = ToolRunner.create_input_file(targets, tmp_path)
        assert result.exists()
        content = result.read_text()
        assert "a.example.com\n" in content
        assert "b.example.com\n" in content

    def test_custom_filename(self, tmp_path):
        result = ToolRunner.create_input_file(["a.com"], tmp_path, filename="custom.txt")
        assert result.name == "custom.txt"

    def test_default_filename(self, tmp_path):
        result = ToolRunner.create_input_file(["a.com"], tmp_path)
        assert result.name == "targets.txt"


class TestExtractDomain:
    def test_extracts_from_url(self):
        assert ToolRunner.extract_domain("https://api.example.com/v1") == "api.example.com"

    def test_extracts_from_http_url(self):
        assert ToolRunner.extract_domain("http://shop.example.com") == "shop.example.com"

    def test_returns_plain_domain(self):
        assert ToolRunner.extract_domain("example.com") == "example.com"

    def test_handles_url_with_port(self):
        assert ToolRunner.extract_domain("https://api.example.com:8443/v2") == "api.example.com"


class TestErrorResult:
    def test_default_error_result(self):
        result = ToolRunner.error_result()
        assert result == {"total": 0, "results": [], "error": None}

    def test_error_result_with_message(self):
        result = ToolRunner.error_result("timeout")
        assert result == {"total": 0, "results": [], "error": "timeout"}

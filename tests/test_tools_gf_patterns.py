import pytest
from unittest.mock import AsyncMock
from bba.tools.gf_patterns import GfPatternsTool
from bba.scope import ScopeConfig, ScopeValidator
from bba.rate_limiter import MultiTargetRateLimiter
from bba.sanitizer import Sanitizer
from bba.tool_runner import ToolRunner
from bba.db import Database

SCOPE = {
    "program": "test-corp",
    "in_scope": {"domains": ["*.example.com", "example.com"]},
}

SAMPLE_URLS = [
    "https://example.com/search?q=test",
    "https://example.com/api?id=123",
    "https://example.com/load?url=https://evil.com",
    "https://example.com/redirect?next=/dashboard",
    "https://example.com/view?file=config.php",
    "https://example.com/exec?cmd=whoami",
    "https://example.com/user?id=42",
    "https://example.com/static/app.js",
    "https://example.com/backup.sql",
]


@pytest.fixture
def scope():
    return ScopeValidator(ScopeConfig.from_dict(SCOPE))


@pytest.fixture
def runner(scope, tmp_path):
    return ToolRunner(scope=scope, rate_limiter=MultiTargetRateLimiter(default_rps=100), sanitizer=Sanitizer(), output_dir=tmp_path / "output")


@pytest.fixture
async def db(tmp_path):
    database = Database(tmp_path / "test.db")
    await database.initialize()
    yield database
    await database.close()


class TestGfPatternsTool:
    def test_classify_xss(self, runner, db):
        tool = GfPatternsTool(runner=runner, db=db, program="test-corp")
        result = tool.classify_urls(["https://example.com/search?q=test"])
        assert len(result["xss"]) == 1

    def test_classify_sqli(self, runner, db):
        tool = GfPatternsTool(runner=runner, db=db, program="test-corp")
        result = tool.classify_urls(["https://example.com/api?id=123"])
        assert len(result["sqli"]) >= 1

    def test_classify_ssrf(self, runner, db):
        tool = GfPatternsTool(runner=runner, db=db, program="test-corp")
        result = tool.classify_urls(["https://example.com/load?url=https://evil.com"])
        assert len(result["ssrf"]) >= 1

    def test_classify_redirect(self, runner, db):
        tool = GfPatternsTool(runner=runner, db=db, program="test-corp")
        result = tool.classify_urls(["https://example.com/redirect?next=/dashboard"])
        assert len(result["redirect"]) >= 1

    def test_classify_lfi(self, runner, db):
        tool = GfPatternsTool(runner=runner, db=db, program="test-corp")
        result = tool.classify_urls(["https://example.com/view?file=config.php"])
        assert len(result["lfi"]) >= 1

    def test_classify_interesting_ext(self, runner, db):
        tool = GfPatternsTool(runner=runner, db=db, program="test-corp")
        result = tool.classify_urls(["https://example.com/backup.sql"])
        assert len(result["interesting-ext"]) == 1

    def test_classify_empty(self, runner, db):
        tool = GfPatternsTool(runner=runner, db=db, program="test-corp")
        result = tool.classify_urls([])
        assert all(len(v) == 0 for v in result.values())

    def test_classify_no_match(self, runner, db):
        tool = GfPatternsTool(runner=runner, db=db, program="test-corp")
        result = tool.classify_urls(["https://example.com/static/image.png"])
        assert all(len(v) == 0 for v in result.values())

    async def test_run_returns_summary(self, runner, db):
        tool = GfPatternsTool(runner=runner, db=db, program="test-corp")
        result = await tool.run(SAMPLE_URLS)
        assert result["total_urls"] == len(SAMPLE_URLS)
        assert result["total_classified"] > 0
        assert "xss" in result["summary"]

    def test_multiple_classifications(self, runner, db):
        tool = GfPatternsTool(runner=runner, db=db, program="test-corp")
        classified = tool.classify_urls(SAMPLE_URLS)
        total = sum(len(v) for v in classified.values())
        assert total >= 6

    def test_classify_ssti(self, runner, db):
        tool = GfPatternsTool(runner=runner, db=db, program="test-corp")
        result = tool.classify_urls(["https://example.com/render?template=index.html"])
        assert len(result["ssti"]) >= 1

    def test_classify_ssti_view_param(self, runner, db):
        tool = GfPatternsTool(runner=runner, db=db, program="test-corp")
        result = tool.classify_urls(["https://example.com/page?view=profile&name=admin"])
        assert len(result["ssti"]) >= 1

    def test_classify_cmdi(self, runner, db):
        tool = GfPatternsTool(runner=runner, db=db, program="test-corp")
        result = tool.classify_urls(["https://example.com/tool?cmd=whoami"])
        assert len(result["cmdi"]) >= 1

    def test_classify_cmdi_exec_param(self, runner, db):
        tool = GfPatternsTool(runner=runner, db=db, program="test-corp")
        result = tool.classify_urls(["https://example.com/api?exec=ls&timeout=30"])
        assert len(result["cmdi"]) >= 1

    def test_classify_crlf(self, runner, db):
        tool = GfPatternsTool(runner=runner, db=db, program="test-corp")
        result = tool.classify_urls(["https://example.com/auth?returnUrl=/dashboard"])
        assert len(result["crlf"]) >= 1

    def test_classify_crlf_location_param(self, runner, db):
        tool = GfPatternsTool(runner=runner, db=db, program="test-corp")
        result = tool.classify_urls(["https://example.com/redirect?location=/home&lang=en"])
        assert len(result["crlf"]) >= 1

    def test_classify_cors(self, runner, db):
        tool = GfPatternsTool(runner=runner, db=db, program="test-corp")
        result = tool.classify_urls(["https://example.com/api?callback=processData"])
        assert len(result["cors"]) >= 1

    def test_classify_cors_jsonp_param(self, runner, db):
        tool = GfPatternsTool(runner=runner, db=db, program="test-corp")
        result = tool.classify_urls(["https://example.com/data?jsonp=handler&cb=func"])
        assert len(result["cors"]) >= 1

    def test_classify_jwt(self, runner, db):
        tool = GfPatternsTool(runner=runner, db=db, program="test-corp")
        result = tool.classify_urls(["https://example.com/api?token=eyJhbGci"])
        assert len(result["jwt"]) >= 1

    def test_classify_jwt_access_token_param(self, runner, db):
        tool = GfPatternsTool(runner=runner, db=db, program="test-corp")
        result = tool.classify_urls(["https://example.com/user?access_token=abc&jwt=xyz"])
        assert len(result["jwt"]) >= 1

    def test_classify_xxe(self, runner, db):
        tool = GfPatternsTool(runner=runner, db=db, program="test-corp")
        result = tool.classify_urls(["https://example.com/parse?xml=data&wsdl=service"])
        assert len(result["xxe"]) >= 1

    def test_classify_xxe_soap_param(self, runner, db):
        tool = GfPatternsTool(runner=runner, db=db, program="test-corp")
        result = tool.classify_urls(["https://example.com/api?soap=payload&export=true"])
        assert len(result["xxe"]) >= 1

    def test_classify_prototype_pollution(self, runner, db):
        tool = GfPatternsTool(runner=runner, db=db, program="test-corp")
        result = tool.classify_urls(["https://example.com/api?__proto__[admin]=1"])
        assert len(result["prototype-pollution"]) >= 1

    def test_classify_prototype_pollution_constructor(self, runner, db):
        tool = GfPatternsTool(runner=runner, db=db, program="test-corp")
        result = tool.classify_urls(["https://example.com/app?constructor[prototype]=x"])
        assert len(result["prototype-pollution"]) >= 1

    def test_classify_upload(self, runner, db):
        tool = GfPatternsTool(runner=runner, db=db, program="test-corp")
        result = tool.classify_urls(["https://example.com/profile?avatar=photo.jpg"])
        assert len(result["upload"]) >= 1

    def test_classify_upload_file_param(self, runner, db):
        tool = GfPatternsTool(runner=runner, db=db, program="test-corp")
        result = tool.classify_urls(["https://example.com/import?file=data.csv&upload=true"])
        assert len(result["upload"]) >= 1

    def test_new_patterns_in_classify_result_keys(self, runner, db):
        tool = GfPatternsTool(runner=runner, db=db, program="test-corp")
        result = tool.classify_urls([])
        for pattern in ["ssti", "cmdi", "crlf", "cors", "jwt", "xxe", "prototype-pollution", "upload"]:
            assert pattern in result

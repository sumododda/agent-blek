import pytest
from pathlib import Path
from bba.scope import ScopeValidator, ScopeConfig


EXAMPLE_SCOPE = {
    "program": "example-corp",
    "platform": "hackerone",
    "in_scope": {
        "domains": [
            "*.example.com",
            "api.example.com",
            "example.com",
        ],
        "cidrs": [
            "192.168.1.0/24",
        ],
    },
    "out_of_scope": {
        "domains": [
            "admin.example.com",
            "*.staging.example.com",
        ],
        "paths": [
            "/logout",
            "/account/delete",
        ],
    },
}


@pytest.fixture
def validator():
    config = ScopeConfig.from_dict(EXAMPLE_SCOPE)
    return ScopeValidator(config)


class TestScopeConfig:
    def test_from_dict(self):
        config = ScopeConfig.from_dict(EXAMPLE_SCOPE)
        assert config.program == "example-corp"
        assert "*.example.com" in config.in_scope_domains
        assert "admin.example.com" in config.out_of_scope_domains

    def test_from_yaml_file(self, tmp_path):
        import yaml
        scope_file = tmp_path / "scope.yaml"
        scope_file.write_text(yaml.dump(EXAMPLE_SCOPE))
        config = ScopeConfig.from_yaml(scope_file)
        assert config.program == "example-corp"

    def test_missing_program_raises(self):
        with pytest.raises(ValueError, match="program"):
            ScopeConfig.from_dict({"in_scope": {"domains": ["*.x.com"]}})

    def test_empty_in_scope_raises(self):
        with pytest.raises(ValueError, match="in_scope"):
            ScopeConfig.from_dict({"program": "test"})


class TestDomainValidation:
    def test_exact_domain_in_scope(self, validator):
        assert validator.is_domain_in_scope("api.example.com") is True

    def test_wildcard_subdomain_in_scope(self, validator):
        assert validator.is_domain_in_scope("shop.example.com") is True

    def test_deep_subdomain_matches_wildcard(self, validator):
        assert validator.is_domain_in_scope("a.b.example.com") is True

    def test_unrelated_domain_out_of_scope(self, validator):
        assert validator.is_domain_in_scope("evil.com") is False

    def test_excluded_domain(self, validator):
        assert validator.is_domain_in_scope("admin.example.com") is False

    def test_excluded_wildcard(self, validator):
        assert validator.is_domain_in_scope("foo.staging.example.com") is False

    def test_base_domain_in_scope(self, validator):
        assert validator.is_domain_in_scope("example.com") is True

    def test_similar_but_different_domain(self, validator):
        assert validator.is_domain_in_scope("notexample.com") is False
        assert validator.is_domain_in_scope("example.com.evil.com") is False


class TestIPValidation:
    def test_ip_in_cidr(self, validator):
        assert validator.is_ip_in_scope("192.168.1.50") is True

    def test_ip_outside_cidr(self, validator):
        assert validator.is_ip_in_scope("10.0.0.1") is False

    def test_ip_at_cidr_boundary(self, validator):
        assert validator.is_ip_in_scope("192.168.1.0") is True
        assert validator.is_ip_in_scope("192.168.1.255") is True
        assert validator.is_ip_in_scope("192.168.2.0") is False


class TestURLValidation:
    def test_url_in_scope(self, validator):
        assert validator.is_url_in_scope("https://shop.example.com/products") is True

    def test_url_excluded_domain(self, validator):
        assert validator.is_url_in_scope("https://admin.example.com/login") is False

    def test_url_excluded_path(self, validator):
        assert validator.is_url_in_scope("https://example.com/logout") is False
        assert validator.is_url_in_scope("https://example.com/account/delete") is False

    def test_url_out_of_scope_domain(self, validator):
        assert validator.is_url_in_scope("https://evil.com/page") is False

    def test_url_with_port(self, validator):
        assert validator.is_url_in_scope("https://api.example.com:8443/v1") is True


class TestTargetValidation:
    def test_validates_domain(self, validator):
        assert validator.validate_target("shop.example.com") is True

    def test_validates_ip(self, validator):
        assert validator.validate_target("192.168.1.100") is True

    def test_validates_url(self, validator):
        assert validator.validate_target("https://api.example.com/v2") is True

    def test_rejects_out_of_scope(self, validator):
        assert validator.validate_target("evil.com") is False

    def test_rejects_excluded(self, validator):
        assert validator.validate_target("admin.example.com") is False

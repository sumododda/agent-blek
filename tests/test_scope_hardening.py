import ipaddress
import os
import pytest
from bba.scope import ScopeConfig, ScopeValidator, _normalize_domain
from bba.scope_importer import ScopeImporter
from bba.config import resolve_api_key


class TestIDNNormalization:
    def test_normalize_ascii_domain(self):
        assert _normalize_domain("Example.COM.") == "example.com"

    def test_normalize_punycode(self):
        result = _normalize_domain("xn--nxasmq6b.example.com")
        assert result == "xn--nxasmq6b.example.com"

    def test_idn_scope_matching(self):
        config = ScopeConfig.from_dict({
            "program": "test",
            "in_scope": {"domains": ["*.example.com"]},
        })
        validator = ScopeValidator(config)
        assert validator.is_domain_in_scope("shop.example.com") is True
        assert validator.is_domain_in_scope("SHOP.EXAMPLE.COM") is True
        assert validator.is_domain_in_scope("shop.example.com.") is True


class TestCIDRValidation:
    def test_valid_cidr_accepted(self):
        importer = ScopeImporter()
        assert importer._is_cidr("10.0.0.0/24") is True

    def test_invalid_cidr_rejected(self):
        importer = ScopeImporter()
        assert importer._is_cidr("999.999.999.999/32") is False

    def test_invalid_octet_rejected(self):
        importer = ScopeImporter()
        assert importer._is_cidr("256.0.0.0/24") is False

    def test_not_cidr_string(self):
        importer = ScopeImporter()
        assert importer._is_cidr("example.com") is False

    def test_ipv6_cidr_accepted(self):
        importer = ScopeImporter()
        assert importer._is_cidr("2001:db8::/32") is True


class TestAPIKeyConfig:
    def test_resolve_env_var(self):
        os.environ["TEST_BBA_KEY"] = "secret123"
        try:
            assert resolve_api_key("${TEST_BBA_KEY}") == "secret123"
        finally:
            del os.environ["TEST_BBA_KEY"]

    def test_resolve_missing_env_var(self):
        assert resolve_api_key("${NONEXISTENT_BBA_KEY_XYZ}") is None

    def test_resolve_literal_value(self):
        assert resolve_api_key("literal-key-value") == "literal-key-value"

    def test_resolve_empty_string(self):
        assert resolve_api_key("") is None

    def test_scope_config_with_api_keys(self):
        os.environ["TEST_SHODAN_KEY"] = "shodan123"
        try:
            config = ScopeConfig.from_dict({
                "program": "test",
                "in_scope": {"domains": ["*.example.com"]},
                "api_keys": {"shodan": "${TEST_SHODAN_KEY}", "custom": "inline-value"},
            })
            assert config.api_keys["shodan"] == "shodan123"
            assert config.api_keys["custom"] == "inline-value"
        finally:
            del os.environ["TEST_SHODAN_KEY"]

    def test_scope_config_without_api_keys(self):
        config = ScopeConfig.from_dict({
            "program": "test",
            "in_scope": {"domains": ["*.example.com"]},
        })
        assert config.api_keys == {}

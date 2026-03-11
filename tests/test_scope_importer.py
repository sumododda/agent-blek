import pytest
import yaml
from bba.scope_importer import ScopeImporter


class TestScopeImporter:
    def test_parse_hackerone_scope(self):
        h1_data = {
            "relationships": {
                "structured_scopes": {
                    "data": [
                        {
                            "attributes": {
                                "asset_type": "URL",
                                "asset_identifier": "*.example.com",
                                "eligible_for_bounty": True,
                                "eligible_for_submission": True,
                                "instruction": "All subdomains",
                            }
                        },
                        {
                            "attributes": {
                                "asset_type": "URL",
                                "asset_identifier": "api.example.com",
                                "eligible_for_bounty": True,
                                "eligible_for_submission": True,
                            }
                        },
                        {
                            "attributes": {
                                "asset_type": "URL",
                                "asset_identifier": "staging.example.com",
                                "eligible_for_bounty": False,
                                "eligible_for_submission": False,
                            }
                        },
                        {
                            "attributes": {
                                "asset_type": "CIDR",
                                "asset_identifier": "10.0.0.0/24",
                                "eligible_for_bounty": True,
                                "eligible_for_submission": True,
                            }
                        },
                    ]
                }
            }
        }
        importer = ScopeImporter()
        scope = importer.parse_hackerone(h1_data, "example-corp")
        assert scope["program"] == "example-corp"
        assert scope["platform"] == "hackerone"
        assert "*.example.com" in scope["in_scope"]["domains"]
        assert "api.example.com" in scope["in_scope"]["domains"]
        assert "10.0.0.0/24" in scope["in_scope"]["cidrs"]
        assert "staging.example.com" in scope["out_of_scope"]["domains"]

    def test_parse_bugcrowd_scope(self):
        bc_data = {
            "target_groups": [
                {
                    "in_scope": True,
                    "targets": [
                        {"name": "*.example.com", "category": "website"},
                        {"name": "api.example.com", "category": "api"},
                    ]
                },
                {
                    "in_scope": False,
                    "targets": [
                        {"name": "blog.example.com", "category": "website"},
                    ]
                },
            ]
        }
        importer = ScopeImporter()
        scope = importer.parse_bugcrowd(bc_data, "example-corp")
        assert scope["program"] == "example-corp"
        assert scope["platform"] == "bugcrowd"
        assert "*.example.com" in scope["in_scope"]["domains"]
        assert "blog.example.com" in scope["out_of_scope"]["domains"]

    def test_to_yaml(self, tmp_path):
        importer = ScopeImporter()
        scope = {
            "program": "test-corp",
            "platform": "hackerone",
            "in_scope": {"domains": ["*.test.com"], "cidrs": []},
            "out_of_scope": {"domains": [], "paths": []},
        }
        output = tmp_path / "test-corp.yaml"
        importer.save_yaml(scope, output)
        assert output.exists()
        loaded = yaml.safe_load(output.read_text())
        assert loaded["program"] == "test-corp"
        assert "*.test.com" in loaded["in_scope"]["domains"]

    def test_normalize_domain(self):
        importer = ScopeImporter()
        assert importer._normalize_asset("https://example.com") == "example.com"
        assert importer._normalize_asset("http://example.com/") == "example.com"
        assert importer._normalize_asset("*.example.com") == "*.example.com"
        assert importer._normalize_asset("example.com") == "example.com"

"""Import program scope from HackerOne/Bugcrowd into our YAML format."""
from __future__ import annotations

import ipaddress
from pathlib import Path
from urllib.parse import urlparse

import yaml


class ScopeImporter:
    """Convert bug bounty platform scope data to our YAML format."""

    def _normalize_asset(self, asset: str) -> str:
        asset = asset.strip()
        if asset.startswith(("http://", "https://")):
            parsed = urlparse(asset)
            return parsed.hostname or asset
        return asset.rstrip("/")

    def _is_cidr(self, asset: str) -> bool:
        try:
            ipaddress.ip_network(asset, strict=False)
            return True
        except ValueError:
            return False

    def parse_hackerone(self, data: dict, program_name: str) -> dict:
        in_domains = []
        in_cidrs = []
        out_domains = []
        scopes = (data.get("relationships", {})
                      .get("structured_scopes", {})
                      .get("data", []))
        for entry in scopes:
            attrs = entry.get("attributes", {})
            asset = attrs.get("asset_identifier", "")
            asset_type = attrs.get("asset_type", "")
            eligible = attrs.get("eligible_for_submission", False)
            normalized = self._normalize_asset(asset)
            if not normalized:
                continue
            if eligible:
                if asset_type == "CIDR" or self._is_cidr(normalized):
                    in_cidrs.append(normalized)
                else:
                    in_domains.append(normalized)
            else:
                if asset_type in ("URL", "WILDCARD"):
                    out_domains.append(normalized)
        return {
            "program": program_name,
            "platform": "hackerone",
            "in_scope": {"domains": in_domains, "cidrs": in_cidrs},
            "out_of_scope": {"domains": out_domains, "paths": []},
        }

    def parse_bugcrowd(self, data: dict, program_name: str) -> dict:
        in_domains = []
        in_cidrs = []
        out_domains = []
        for group in data.get("target_groups", []):
            in_scope = group.get("in_scope", True)
            for target in group.get("targets", []):
                asset = self._normalize_asset(target.get("name", ""))
                if not asset:
                    continue
                if in_scope:
                    if self._is_cidr(asset):
                        in_cidrs.append(asset)
                    else:
                        in_domains.append(asset)
                else:
                    out_domains.append(asset)
        return {
            "program": program_name,
            "platform": "bugcrowd",
            "in_scope": {"domains": in_domains, "cidrs": in_cidrs},
            "out_of_scope": {"domains": out_domains, "paths": []},
        }

    def save_yaml(self, scope: dict, output_path: Path):
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(yaml.dump(scope, default_flow_style=False, sort_keys=False))

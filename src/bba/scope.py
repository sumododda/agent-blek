from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlparse

import yaml

from bba.config import resolve_api_key


@dataclass
class ScopeConfig:
    program: str
    platform: str = ""
    in_scope_domains: list[str] = field(default_factory=list)
    in_scope_cidrs: list[str] = field(default_factory=list)
    out_of_scope_domains: list[str] = field(default_factory=list)
    out_of_scope_paths: list[str] = field(default_factory=list)
    api_keys: dict[str, str | None] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: dict) -> ScopeConfig:
        if "program" not in data:
            raise ValueError("Scope config must include 'program'")
        in_scope = data.get("in_scope")
        if not in_scope or not in_scope.get("domains"):
            raise ValueError("Scope config must include 'in_scope' with at least one domain")
        out_scope = data.get("out_of_scope", {})
        raw_keys = data.get("api_keys", {})
        resolved_keys = {k: resolve_api_key(v) for k, v in raw_keys.items()}
        return cls(
            program=data["program"],
            platform=data.get("platform", ""),
            in_scope_domains=in_scope.get("domains", []),
            in_scope_cidrs=in_scope.get("cidrs", []),
            out_of_scope_domains=out_scope.get("domains", []),
            out_of_scope_paths=out_scope.get("paths", []),
            api_keys=resolved_keys,
        )

    @classmethod
    def from_yaml(cls, path: Path) -> ScopeConfig:
        data = yaml.safe_load(path.read_text())
        return cls.from_dict(data)


def _normalize_domain(domain: str) -> str:
    domain = domain.lower().rstrip(".")
    try:
        domain = domain.encode("idna").decode("ascii")
    except (UnicodeError, UnicodeDecodeError):
        pass
    return domain


def _domain_matches(pattern: str, domain: str) -> bool:
    domain = _normalize_domain(domain)
    pattern = _normalize_domain(pattern)

    if pattern == domain:
        return True

    if pattern.startswith("*."):
        suffix = pattern[1:]
        return domain.endswith(suffix) and domain != suffix.lstrip(".")

    return False


class ScopeValidator:
    def __init__(self, config: ScopeConfig):
        self.config = config
        self._networks = [
            ipaddress.ip_network(cidr, strict=False)
            for cidr in config.in_scope_cidrs
        ]

    def is_domain_in_scope(self, domain: str) -> bool:
        domain = _normalize_domain(domain)

        for pattern in self.config.out_of_scope_domains:
            if _domain_matches(pattern, domain):
                return False

        for pattern in self.config.in_scope_domains:
            if _domain_matches(pattern, domain):
                return True

        return False

    def is_ip_in_scope(self, ip: str) -> bool:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False
        return any(addr in net for net in self._networks)

    def is_url_in_scope(self, url: str) -> bool:
        parsed = urlparse(url)
        hostname = parsed.hostname or ""

        if not self.is_domain_in_scope(hostname):
            return False

        path = parsed.path.rstrip("/")
        for excluded_path in self.config.out_of_scope_paths:
            if path == excluded_path.rstrip("/") or path.startswith(excluded_path.rstrip("/") + "/"):
                return False

        return True

    def validate_target(self, target: str) -> bool:
        if "://" in target:
            return self.is_url_in_scope(target)

        try:
            ipaddress.ip_address(target)
            return self.is_ip_in_scope(target)
        except ValueError:
            pass

        return self.is_domain_in_scope(target)

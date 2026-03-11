from __future__ import annotations

import json
import subprocess
from pathlib import Path

WORDLIST_DIR = Path(__file__).resolve().parent.parent.parent / "data" / "wordlists"

WORDLISTS = {
    "seclists": {
        "url": "https://github.com/danielmiessler/SecLists.git",
        "type": "git",
        "paths": {
            "dns": "Discovery/DNS",
            "web-content": "Discovery/Web-Content",
            "fuzzing": "Fuzzing",
        },
    },
    "assetnote-best-dns": {
        "url": "https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt",
        "type": "file",
    },
    "onelistforall": {
        "url": "https://raw.githubusercontent.com/six2dez/OneListForAll/main/onelistforallmicro.txt",
        "type": "file",
    },
    "resolvers": {
        "url": "https://raw.githubusercontent.com/trickest/resolvers/main/resolvers.txt",
        "type": "file",
    },
}


class WordlistManager:
    def __init__(self, wordlist_dir: Path = WORDLIST_DIR):
        self.wordlist_dir = wordlist_dir
        self.manifest_path = wordlist_dir / "manifest.json"

    def list(self) -> dict:
        """List available and downloaded wordlists."""
        result = {}
        for name, info in WORDLISTS.items():
            path = self.wordlist_dir / name
            result[name] = {
                "available": True,
                "downloaded": path.exists(),
                "type": info["type"],
                "path": str(path) if path.exists() else None,
            }
        return result

    def download(self, name: str = "all") -> dict:
        """Download wordlist(s). Pass 'all' for everything."""
        self.wordlist_dir.mkdir(parents=True, exist_ok=True)
        targets = WORDLISTS if name == "all" else {name: WORDLISTS[name]}
        results = {}
        for wl_name, info in targets.items():
            dest = self.wordlist_dir / wl_name
            if dest.exists():
                results[wl_name] = {"status": "exists", "path": str(dest)}
                continue
            try:
                if info["type"] == "git":
                    subprocess.run(
                        ["git", "clone", "--depth", "1", info["url"], str(dest)],
                        check=True, capture_output=True,
                    )
                else:
                    dest.parent.mkdir(parents=True, exist_ok=True)
                    subprocess.run(
                        ["curl", "-fsSL", info["url"], "-o", str(dest)],
                        check=True, capture_output=True,
                    )
                results[wl_name] = {"status": "downloaded", "path": str(dest)}
            except subprocess.CalledProcessError as e:
                results[wl_name] = {"status": "failed", "error": e.stderr.decode(errors="replace")}
        self._save_manifest(results)
        return results

    def get_path(self, name: str, subpath: str = "") -> Path | None:
        """Get path to a specific wordlist."""
        path = self.wordlist_dir / name
        if subpath:
            path = path / subpath
        return path if path.exists() else None

    def _save_manifest(self, results: dict) -> None:
        existing = {}
        if self.manifest_path.exists():
            existing = json.loads(self.manifest_path.read_text())
        existing.update(results)
        self.manifest_path.write_text(json.dumps(existing, indent=2))

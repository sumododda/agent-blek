import pytest
from pathlib import Path


class TestDefaultWordlistPaths:
    def test_cli_default_wordlist_is_relative(self):
        from bba.cli import DEFAULT_WORDLIST
        assert "/home/sumo" not in DEFAULT_WORDLIST
        assert "agent-blek" not in DEFAULT_WORDLIST or DEFAULT_WORDLIST.startswith(str(Path(__file__).resolve().parent.parent))

    def test_feroxbuster_default_wordlist_is_relative(self):
        from bba.tools.feroxbuster import DEFAULT_WORDLIST
        assert "/home/sumo" not in DEFAULT_WORDLIST

    def test_cli_wordlist_under_data_dir(self):
        from bba.cli import DEFAULT_WORDLIST, DATA_DIR
        assert DEFAULT_WORDLIST.startswith(str(DATA_DIR))

    def test_feroxbuster_wordlist_path_structure(self):
        from bba.tools.feroxbuster import DEFAULT_WORDLIST
        assert "seclists" in DEFAULT_WORDLIST
        assert "common.txt" in DEFAULT_WORDLIST

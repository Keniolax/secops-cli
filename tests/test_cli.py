"""Tests for the command line: JSON output, exit codes, errors on stderr."""

import json
from pathlib import Path

from secops_cli.cli import main

AUTH_LOG = str(Path(__file__).parent / "data" / "auth.log")


def test_logs_json_is_valid_and_exit_code_says_findings(capsys):
    code = main(["logs", AUTH_LOG, "--year", "2026", "--json"])
    out = capsys.readouterr().out
    assert code == 1
    assert json.loads(out)["brute_force"][0]["ip"] == "172.18.0.6"


def test_logs_text_mode(capsys):
    main(["logs", AUTH_LOG, "--year", "2026"])
    out = capsys.readouterr().out
    assert "BRUTE FORCE  172.18.0.6" in out


def test_out_of_scope_scan_exits_2_and_writes_only_to_stderr(capsys):
    code = main(["scan", "8.8.8.8", "-p", "53", "--json"])
    captured = capsys.readouterr()
    assert code == 2
    assert captured.out == ""
    assert "outside the allowed networks" in captured.err


def test_missing_log_file_exits_2(capsys):
    assert main(["logs", "/no/such/file"]) == 2
    assert "error" in capsys.readouterr().err


def test_fim_round_trip(tmp_path, capsys):
    root = tmp_path / "w"
    root.mkdir()
    (root / "a").write_text("1")
    base, key = str(tmp_path / "b.json"), str(tmp_path / "k")
    assert main(["fim", "init", str(root), "--baseline", base, "--key-file", key]) == 0
    assert main(["fim", "check", "--baseline", base, "--key-file", key]) == 0
    (root / "a").write_text("2")
    capsys.readouterr()
    assert main(["fim", "check", "--baseline", base, "--key-file", key, "--json"]) == 1
    assert json.loads(capsys.readouterr().out)["modified"][0]["path"] == "a"

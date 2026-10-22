"""Tests for SSH log triage.

data/auth.log is modelled on the sshd lines that home-soc-lab's victim wrote
during its week 1 brute-force test, plus a slow attacker, a cron line and an
accepted key login.
"""

from pathlib import Path

from secops_cli import logs
from secops_cli.output import FINDINGS, OK

DATA = Path(__file__).parent / "data" / "auth.log"


def lines():
    return DATA.read_text().splitlines()


def test_parses_invalid_user_line():
    e = logs.parse_line(
        "Oct 20 00:24:44 victim sshd[2335]: Invalid user probe-1 from 172.18.0.6 port 50802", 2026
    )
    assert e is not None
    assert (e.kind, e.user, e.ip, e.host) == ("invalid_user", "probe-1", "172.18.0.6", "victim")
    assert e.time.isoformat() == "2026-10-20T00:24:44+00:00"


def test_parses_iso_timestamp_and_sshd_session():
    e = logs.parse_line(
        "2026-10-20T00:24:44.123456+00:00 victim sshd-session[9]: "
        "Failed password for invalid user bob from 10.0.0.5 port 4242 ssh2",
        1999,
    )
    assert e is not None
    assert (e.kind, e.user, e.ip) == ("failed_password", "bob", "10.0.0.5")
    assert e.time.year == 2026  # the line's own year wins over the fallback


def test_ignores_lines_that_are_not_sshd_events():
    assert logs.parse_line("Oct 20 00:25:01 victim CRON[2400]: session opened", 2026) is None
    assert (
        logs.parse_line(
            "Oct 20 00:24:44 victim sshd[1]: Connection closed by 1.2.3.4 [preauth]", 2026
        )
        is None
    )
    assert logs.parse_line("not a log line", 2026) is None


def test_flags_the_fast_attacker_and_not_the_slow_one():
    report = logs.triage(lines(), year=2026)
    assert report.exit_code == FINDINGS
    flagged = [b["ip"] for b in report.data["brute_force"]]
    # 12 failures in one second: flagged. 8 failures over 9 minutes: not flagged.
    assert flagged == ["172.18.0.6"]
    assert report.data["brute_force"][0]["failures_in_window"] == 8


def test_counts_sources_and_accepted_logins():
    data = logs.triage(lines(), year=2026).data
    by_ip = {s["ip"]: s["failures"] for s in data["sources"]}
    assert by_ip == {"172.18.0.6": 12, "198.51.100.7": 8}
    assert data["accepted"] == [
        {"time": "2026-10-20T01:20:00+00:00", "user": "kolade", "ip": "192.0.2.10"}
    ]


def test_slow_attacker_is_flagged_with_a_wider_window():
    report = logs.triage(lines(), year=2026, window=600)
    assert {b["ip"] for b in report.data["brute_force"]} == {"172.18.0.6", "198.51.100.7"}


def test_window_edge_is_inclusive():
    # 8 failures exactly 120 seconds apart from first to last: inside the window.
    base = "Oct 20 00:00:{:02d} h sshd[1]: Invalid user x from 10.0.0.9 port 1"
    edge = [base.format(0)] * 7 + ["Oct 20 00:02:00 h sshd[1]: Invalid user x from 10.0.0.9 port 1"]
    assert logs.triage(edge, year=2026).exit_code == FINDINGS
    late = edge[:-1] + ["Oct 20 00:02:01 h sshd[1]: Invalid user x from 10.0.0.9 port 1"]
    assert logs.triage(late, year=2026).exit_code == OK


def test_empty_log_is_ok():
    report = logs.triage([], year=2026)
    assert report.exit_code == OK
    assert report.data["events"] == 0

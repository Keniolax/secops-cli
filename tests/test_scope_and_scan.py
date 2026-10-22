"""Tests for the scope check and the port scanner.

Only one test opens real sockets, and only on 127.0.0.1 against a listener
the test starts itself, so nothing here depends on the internet.
"""

import socket

import pytest

from secops_cli import scan
from secops_cli.scope import ScopeError, parse_networks, resolve_in_scope


def fixed(*addresses):
    return lambda host: list(addresses)


def test_loopback_is_in_scope_by_default():
    assert str(resolve_in_scope("x", resolver=fixed("127.0.0.1"))) == "127.0.0.1"


def test_public_address_is_refused():
    with pytest.raises(ScopeError, match="outside the allowed networks"):
        resolve_in_scope("x", resolver=fixed("8.8.8.8"))


def test_allowed_network_is_in_scope():
    lab = parse_networks(["172.18.0.0/16"])
    assert str(resolve_in_scope("victim", lab, fixed("172.18.0.4"))) == "172.18.0.4"


def test_name_with_any_address_outside_scope_is_refused():
    lab = parse_networks(["172.18.0.0/16"])
    with pytest.raises(ScopeError, match="203.0.113.9"):
        resolve_in_scope("mixed", lab, fixed("172.18.0.4", "203.0.113.9"))


def test_bad_allow_value_is_an_error():
    with pytest.raises(ScopeError, match="not a network"):
        parse_networks(["not-a-cidr"])


def test_unresolvable_name_is_an_error():
    def fails(host):
        raise OSError("no such host")

    with pytest.raises(ScopeError, match="cannot resolve"):
        resolve_in_scope("nowhere", resolver=fails)


@pytest.mark.parametrize(
    ("spec", "expected"),
    [
        ("22", [22]),
        ("80,22,22", [22, 80]),
        ("8000-8002", [8000, 8001, 8002]),
        (" 1 , 3-4 ", [1, 3, 4]),
    ],
)
def test_parse_ports(spec, expected):
    assert scan.parse_ports(spec) == expected


@pytest.mark.parametrize("spec", ["0", "70000", "10-5", "abc", "", "1-2000"])
def test_parse_ports_rejects(spec):
    with pytest.raises(ValueError):
        scan.parse_ports(spec)


def test_scan_reports_what_connect_returns():
    states = {22: "open", 80: "closed", 443: "filtered"}
    report = scan.scan(
        "x", [22, 80, 443], resolver=fixed("127.0.0.1"), connect=lambda a, p, t: states[p]
    )
    assert report.data["open"] == [22]
    assert [r["state"] for r in report.data["results"]] == ["open", "closed", "filtered"]


def test_scan_out_of_scope_sends_nothing():
    calls = []
    with pytest.raises(ScopeError):
        scan.scan("x", [22], resolver=fixed("8.8.8.8"), connect=lambda *a: calls.append(a))
    assert calls == []


def test_real_connect_on_loopback():
    with socket.socket() as server:
        server.bind(("127.0.0.1", 0))
        server.listen()
        open_port = server.getsockname()[1]
        # A port with no socket at all answers with a reset: "closed". (A socket that
        # is bound but not listening is different: macOS drops the SYN silently,
        # which looks like a firewall, so the scanner rightly says "filtered".)
        with socket.socket() as spare:
            spare.bind(("127.0.0.1", 0))
            closed_port = spare.getsockname()[1]
        assert scan.tcp_connect("127.0.0.1", open_port, 1.0) == "open"
        assert scan.tcp_connect("127.0.0.1", closed_port, 1.0) == "closed"

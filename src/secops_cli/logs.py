"""SSH log triage: who failed to log in, from where, and how fast.

Reads sshd lines from an auth log and flags a brute force with the same
logic as Wazuh rule 5712: THRESHOLD or more failed logins from one source
address within WINDOW seconds.

Two timestamp formats are understood:
  classic  Oct 20 00:24:44 victim sshd[2335]: ...   (no year in the line)
  ISO      2026-10-20T00:24:44.123456+00:00 victim sshd[2335]: ...
"""

from __future__ import annotations

import re
from collections import defaultdict
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import UTC, datetime

from .output import FINDINGS, OK, Report

THRESHOLD = 8
WINDOW = 120

CLASSIC = re.compile(
    r"^(?P<ts>[A-Z][a-z]{2} [ \d]\d \d{2}:\d{2}:\d{2}) (?P<host>\S+) (?P<rest>.*)$"
)
ISO = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})?)"
    r" (?P<host>\S+) (?P<rest>.*)$"
)
SSHD = re.compile(r"^sshd(?:-session)?\[\d+\]: (?P<msg>.*)$")

# Order matters: the first pattern that matches decides the event type.
EVENTS = [
    ("invalid_user", re.compile(r"^Invalid user (?P<user>\S*) from (?P<ip>\S+) port \d+")),
    (
        "failed_password",
        re.compile(
            r"^Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>\S+) port \d+"
        ),
    ),
    ("accepted", re.compile(r"^Accepted \S+ for (?P<user>\S+) from (?P<ip>\S+) port \d+")),
]
FAILURES = {"invalid_user", "failed_password"}


@dataclass(frozen=True)
class Event:
    time: datetime
    host: str
    kind: str
    user: str
    ip: str


def parse_time(text: str, year: int) -> datetime:
    if text[0].isdigit():
        stamp = datetime.fromisoformat(text.replace("Z", "+00:00"))
        return stamp if stamp.tzinfo else stamp.replace(tzinfo=UTC)
    # Classic syslog has no year and no zone; take both from the caller.
    return datetime.strptime(f"{year} {text}", "%Y %b %d %H:%M:%S").replace(tzinfo=UTC)


def parse_line(line: str, year: int) -> Event | None:
    """Return the sshd event on LINE, or None if the line is not one."""
    line = line.rstrip("\n")
    head = CLASSIC.match(line) or ISO.match(line)
    if not head:
        return None
    sshd = SSHD.match(head["rest"])
    if not sshd:
        return None
    for kind, pattern in EVENTS:
        m = pattern.match(sshd["msg"])
        if m:
            try:
                when = parse_time(head["ts"], year)
            except ValueError:
                return None
            return Event(when, head["host"], kind, m["user"], m["ip"])
    return None


def find_bursts(events: Iterable[Event], threshold: int, window: int) -> list[dict]:
    """Find each source address with THRESHOLD failures inside WINDOW seconds."""
    by_ip: dict[str, list[datetime]] = defaultdict(list)
    for e in events:
        if e.kind in FAILURES:
            by_ip[e.ip].append(e.time)

    bursts = []
    for ip, times in by_ip.items():
        times.sort()
        start = 0
        # Sliding window: grow on the right, shrink on the left.
        for end, t in enumerate(times):
            while (t - times[start]).total_seconds() > window:
                start += 1
            if end - start + 1 >= threshold:
                bursts.append(
                    {
                        "ip": ip,
                        "failures_in_window": end - start + 1,
                        "first": times[start].isoformat(),
                        "last": t.isoformat(),
                    }
                )
                break
    return sorted(bursts, key=lambda b: b["ip"])


def triage(
    lines: Iterable[str],
    *,
    year: int | None = None,
    threshold: int = THRESHOLD,
    window: int = WINDOW,
) -> Report:
    year = year or datetime.now(UTC).year
    events = [e for e in (parse_line(line, year) for line in lines) if e]

    failures_by_ip: dict[str, int] = defaultdict(int)
    users_by_ip: dict[str, set[str]] = defaultdict(set)
    accepted = []
    for e in events:
        if e.kind in FAILURES:
            failures_by_ip[e.ip] += 1
            users_by_ip[e.ip].add(e.user)
        elif e.kind == "accepted":
            accepted.append({"time": e.time.isoformat(), "user": e.user, "ip": e.ip})

    bursts = find_bursts(events, threshold, window)
    sources = [
        {"ip": ip, "failures": n, "users": sorted(users_by_ip[ip])}
        for ip, n in sorted(failures_by_ip.items(), key=lambda kv: (-kv[1], kv[0]))
    ]
    data = {
        "events": len(events),
        "failures": sum(failures_by_ip.values()),
        "sources": sources,
        "accepted": accepted,
        "brute_force": bursts,
        "rule": {"threshold": threshold, "window_seconds": window},
    }

    n = len(sources)
    lines_out = [
        f"{len(events)} sshd events, {data['failures']} failed logins "
        f"from {n} source{'' if n == 1 else 's'}"
    ]
    for s in sources[:10]:
        lines_out.append(
            f"  {s['ip']:<39} {s['failures']:>5} failures  users: {', '.join(s['users'][:5])}"
        )
    for b in bursts:
        lines_out.append(
            f"BRUTE FORCE  {b['ip']}: {b['failures_in_window']} failures "
            f"between {b['first']} and {b['last']}"
        )
    for a in accepted:
        lines_out.append(f"accepted     {a['user']} from {a['ip']} at {a['time']}")
    return Report(data=data, lines=lines_out, exit_code=FINDINGS if bursts else OK)

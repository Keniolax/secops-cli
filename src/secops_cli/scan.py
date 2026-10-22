"""TCP connect scan.

A connect scan completes the TCP handshake on each port. It needs no root
access and is the most polite kind of scan, but every open port it finds
shows up in the target's logs as a connection.

Each port ends in one of three states:
  open      the handshake completed
  closed    the host answered with a reset (ConnectionRefusedError)
  filtered  no answer before the timeout, which usually means a firewall
"""

from __future__ import annotations

import socket
from collections.abc import Callable, Iterable
from concurrent.futures import ThreadPoolExecutor

from .output import Report
from .scope import DEFAULT_ALLOWED, IPNetwork, Resolver, resolve_in_scope, system_resolver

MAX_PORTS = 1024
# connect(address, port, timeout) -> "open" | "closed" | "filtered"
Connector = Callable[[str, int, float], str]


def tcp_connect(address: str, port: int, timeout: float) -> str:
    """Try one TCP handshake and report the port's state."""
    try:
        with socket.create_connection((address, port), timeout=timeout):
            return "open"
    except ConnectionRefusedError:
        return "closed"
    except TimeoutError:
        return "filtered"
    except OSError:
        # Host or network unreachable: nothing answered.
        return "filtered"


def parse_ports(spec: str) -> list[int]:
    """Turn '22,80,8000-8010' into a sorted list of unique ports."""
    ports: set[int] = set()
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        try:
            if "-" in part:
                low_text, high_text = part.split("-", 1)
                low, high = int(low_text), int(high_text)
            else:
                low = high = int(part)
        except ValueError as exc:
            raise ValueError(f"bad port range {part!r}") from exc
        if not (1 <= low <= high <= 65535):
            raise ValueError(f"port range {part!r} must be within 1-65535, low to high")
        ports.update(range(low, high + 1))
        if len(ports) > MAX_PORTS:
            raise ValueError(f"more than {MAX_PORTS} ports; scan in smaller ranges")
    if not ports:
        raise ValueError("no ports given")
    return sorted(ports)


def scan(
    host: str,
    ports: Iterable[int],
    *,
    allowed: Iterable[IPNetwork] = DEFAULT_ALLOWED,
    timeout: float = 0.5,
    workers: int = 32,
    connect: Connector = tcp_connect,
    resolver: Resolver = system_resolver,
) -> Report:
    """Scan PORTS on HOST. Tests pass a fake connect() and resolver()."""
    address = str(resolve_in_scope(host, allowed, resolver))
    ports = list(ports)
    with ThreadPoolExecutor(max_workers=max(1, min(workers, len(ports)))) as pool:
        states = list(pool.map(lambda p: connect(address, p, timeout), ports))

    results = [{"port": p, "state": s} for p, s in zip(ports, states, strict=True)]
    open_ports = [r["port"] for r in results if r["state"] == "open"]
    data = {
        "host": host,
        "address": address,
        "ports_scanned": len(ports),
        "open": open_ports,
        "results": results,
    }
    lines = [f"{host} ({address}): {len(open_ports)} open of {len(ports)} scanned"]
    lines += [f"  {r['port']:>5}/tcp  {r['state']}" for r in results if r["state"] == "open"]
    return Report(data=data, lines=lines)

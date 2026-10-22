"""Decide which hosts the tools may touch.

The scanner and the TLS checker connect to other machines. Both call
resolve_in_scope() first, and both then connect to the address it returns,
never to the host name again. A second lookup could return a different
address than the one that was checked.
"""

from __future__ import annotations

import ipaddress
import socket
from collections.abc import Callable, Iterable

IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address
IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network

# Without --allow, only this machine is in scope.
DEFAULT_ALLOWED: tuple[IPNetwork, ...] = (
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("::1/128"),
)

Resolver = Callable[[str], list[str]]


class ScopeError(Exception):
    """The target is outside the allowed networks, or cannot be resolved."""


def system_resolver(host: str) -> list[str]:
    """Return every address the operating system resolves HOST to."""
    infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    return sorted({str(info[4][0]) for info in infos})


def parse_networks(values: Iterable[str]) -> tuple[IPNetwork, ...]:
    """Turn --allow values such as '172.18.0.0/16' into networks."""
    networks = []
    for value in values:
        try:
            networks.append(ipaddress.ip_network(value, strict=False))
        except ValueError as exc:
            raise ScopeError(f"--allow {value!r} is not a network: {exc}") from exc
    return tuple(networks)


def resolve_in_scope(
    host: str,
    allowed: Iterable[IPNetwork] = DEFAULT_ALLOWED,
    resolver: Resolver = system_resolver,
) -> IPAddress:
    """Return the address to connect to, or raise ScopeError.

    Every address that HOST resolves to must be in scope, not only the
    first. A name that resolves to one lab address and one public address
    is refused.
    """
    allowed = tuple(allowed)
    try:
        addresses = [ipaddress.ip_address(a) for a in resolver(host)]
    except (OSError, ValueError) as exc:
        raise ScopeError(f"cannot resolve {host!r}: {exc}") from exc
    if not addresses:
        raise ScopeError(f"{host!r} resolved to no addresses")

    outside = [a for a in addresses if not any(a in net for net in allowed)]
    if outside:
        nets = ", ".join(str(n) for n in allowed)
        raise ScopeError(
            f"{host!r} resolves to {', '.join(map(str, outside))}, outside the allowed "
            f"networks ({nets}). Add a network you own with --allow."
        )
    return addresses[0]

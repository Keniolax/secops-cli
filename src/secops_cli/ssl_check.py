"""TLS certificate check: is it trusted, which names does it cover, when does it expire.

There is no option to switch verification off. A checker that skips
verification says "fine" about exactly the certificates that are not. For a
lab with its own certificate authority, pass that CA with --cafile.
"""

from __future__ import annotations

import socket
import ssl
from collections.abc import Callable, Iterable
from datetime import UTC, datetime
from typing import Any

from .output import FINDINGS, OK, Report
from .scope import DEFAULT_ALLOWED, IPNetwork, Resolver, resolve_in_scope, system_resolver

WARN_DAYS = 30
# fetch(address, port, server_name, context, timeout) -> ssl.getpeercert() dict
Fetcher = Callable[[str, int, str, ssl.SSLContext, float], dict[str, Any]]


def fetch_cert(
    address: str, port: int, server_name: str, context: ssl.SSLContext, timeout: float
) -> dict:
    """Connect to the checked ADDRESS, ask for SERVER_NAME (SNI), return the verified cert."""
    with (
        socket.create_connection((address, port), timeout=timeout) as raw,
        context.wrap_socket(raw, server_hostname=server_name) as tls,
    ):
        return tls.getpeercert()


def _name(rdns: Iterable) -> dict[str, str]:
    """Flatten getpeercert()'s ((('commonName', 'x'),), ...) into {'commonName': 'x'}."""
    return {k: v for rdn in rdns for (k, v) in rdn}


def summarise(cert: dict[str, Any], now: datetime) -> dict[str, Any]:
    not_after = datetime.fromtimestamp(ssl.cert_time_to_seconds(cert["notAfter"]), UTC)
    not_before = datetime.fromtimestamp(ssl.cert_time_to_seconds(cert["notBefore"]), UTC)
    return {
        "subject": _name(cert.get("subject", ())),
        "issuer": _name(cert.get("issuer", ())),
        "san": [
            value for kind, value in cert.get("subjectAltName", ()) if kind in ("DNS", "IP Address")
        ],
        "not_before": not_before.isoformat(),
        "not_after": not_after.isoformat(),
        "days_left": (not_after - now).days,
        "serial": cert.get("serialNumber"),
    }


def check(
    host: str,
    port: int = 443,
    *,
    cafile: str | None = None,
    warn_days: int = WARN_DAYS,
    allowed: Iterable[IPNetwork] = DEFAULT_ALLOWED,
    timeout: float = 5.0,
    fetch: Fetcher = fetch_cert,
    resolver: Resolver = system_resolver,
    now: datetime | None = None,
) -> Report:
    address = str(resolve_in_scope(host, allowed, resolver))
    now = now or datetime.now(UTC)
    context = ssl.create_default_context(cafile=cafile)
    target = f"{host}:{port}"

    try:
        cert = fetch(address, port, host, context, timeout)
    except ssl.SSLCertVerificationError as exc:
        reason = exc.verify_message or str(exc)
        data = {"target": target, "address": address, "verified": False, "error": reason}
        return Report(data=data, lines=[f"{target}: NOT TRUSTED: {reason}"], exit_code=FINDINGS)

    info = summarise(cert, now)
    problems = []
    if info["days_left"] < 0:
        problems.append(f"expired {-info['days_left']} days ago")
    elif info["days_left"] < warn_days:
        problems.append(f"expires in {info['days_left']} days (warning at {warn_days})")

    data = {"target": target, "address": address, "verified": True, **info, "problems": problems}
    lines = [
        f"{target}: trusted, expires {info['not_after']} ({info['days_left']} days)",
        f"  subject: {info['subject'].get('commonName', '-')}",
        f"  issuer:  {info['issuer'].get('commonName', '-')}",
        f"  names:   {', '.join(info['san']) or '-'}",
    ]
    lines += [f"  PROBLEM: {p}" for p in problems]
    return Report(data=data, lines=lines, exit_code=FINDINGS if problems else OK)

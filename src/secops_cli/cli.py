"""The `secops` command: one entry point for every tool.

Exit codes: 0 nothing to report, 1 findings, 2 could not run.
Results go to stdout. Errors go to stderr, so piped JSON stays clean.
"""

from __future__ import annotations

import argparse
import contextlib
import json
import signal
import sys
import threading
from pathlib import Path

from . import __version__, fim, logs, scan, ssl_check
from .output import ERROR, OK, Report, emit
from .scope import DEFAULT_ALLOWED, ScopeError, parse_networks


def _allowed(args: argparse.Namespace):
    return DEFAULT_ALLOWED + parse_networks(args.allow)


def cmd_scan(args: argparse.Namespace) -> Report:
    ports = scan.parse_ports(args.ports)
    return scan.scan(
        args.host, ports, allowed=_allowed(args), timeout=args.timeout, workers=args.workers
    )


def cmd_logs(args: argparse.Namespace) -> Report:
    with open(args.file, encoding="utf-8", errors="replace") as f:
        return logs.triage(f, year=args.year, threshold=args.threshold, window=args.window)


def cmd_ssl(args: argparse.Namespace) -> Report:
    host, _, port = args.target.rpartition(":")
    if not host or not port.isdigit():
        host, port = args.target, "443"
    return ssl_check.check(
        host, int(port), cafile=args.cafile, warn_days=args.warn_days, allowed=_allowed(args)
    )


def cmd_fim_init(args: argparse.Namespace) -> Report:
    return fim.init(
        Path(args.root),
        Path(args.baseline),
        key_file=Path(args.key_file),
        exclude=args.exclude,
        force=args.force,
    )


def cmd_fim_check(args: argparse.Namespace) -> Report:
    return fim.check(Path(args.baseline), key_file=Path(args.key_file))


def cmd_fim_watch(args: argparse.Namespace) -> Report:
    stop = threading.Event()
    # launchd and systemd stop a job with SIGTERM; treat it like Ctrl-C.
    signal.signal(signal.SIGTERM, lambda *_: stop.set())
    found = threading.Event()

    def report(event: dict) -> None:
        if event.get("event") == "change" or event.get("exit_code") == 1:
            found.set()
        if args.json:
            # JSON Lines: one object per line, so a reader can process each as it arrives.
            print(json.dumps(event, sort_keys=True, default=str), flush=True)
        elif event["event"] == "change":
            print(f"{event['time']}  {event['state'].upper():<9} {event['path']}", flush=True)
        else:
            n = len(event["added"]) + len(event["removed"]) + len(event["modified"])
            print(
                f"{event['checked']}  RESCAN ({event['reason']}): {n} change(s) since baseline",
                flush=True,
            )

    with contextlib.suppress(KeyboardInterrupt):
        fim.watch(
            Path(args.baseline),
            key_file=Path(args.key_file),
            rescan=args.rescan,
            report=report,
            stop=stop,
        )
    return Report(data={}, lines=[], exit_code=1 if found.is_set() else OK)


def build_parser() -> argparse.ArgumentParser:
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--json", action="store_true", help="print results as JSON")

    scoped = argparse.ArgumentParser(add_help=False)
    scoped.add_argument(
        "--allow",
        action="append",
        default=[],
        metavar="CIDR",
        help="a network you own that may be contacted, e.g. 172.18.0.0/16 (repeatable). "
        "Loopback is always allowed; nothing else is by default.",
    )

    parser = argparse.ArgumentParser(
        prog="secops", description="Small security tools for a home lab."
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("scan", parents=[common, scoped], help="TCP connect scan of hosts you own")
    p.add_argument("host")
    p.add_argument("-p", "--ports", default="1-1024", help="e.g. 22,80,8000-8100 (default 1-1024)")
    p.add_argument("--timeout", type=float, default=0.5, help="seconds per port (default 0.5)")
    p.add_argument("--workers", type=int, default=32, help="ports tried at once (default 32)")
    p.set_defaults(func=cmd_scan)

    p = sub.add_parser("logs", parents=[common], help="triage sshd lines in an auth log")
    p.add_argument("file", help="e.g. /var/log/auth.log")
    p.add_argument(
        "--year",
        type=int,
        help="year for classic syslog lines, which have none (default: this year)",
    )
    p.add_argument(
        "--threshold",
        type=int,
        default=logs.THRESHOLD,
        help="failures that make a brute force (default 8)",
    )
    p.add_argument(
        "--window",
        type=int,
        default=logs.WINDOW,
        help="seconds the failures must fall in (default 120)",
    )
    p.set_defaults(func=cmd_logs)

    p = sub.add_parser("ssl", parents=[common, scoped], help="check a TLS certificate")
    p.add_argument("target", help="host or host:port (default port 443)")
    p.add_argument("--cafile", help="trust this CA too, e.g. a lab's own root CA")
    p.add_argument(
        "--warn-days",
        type=int,
        default=ssl_check.WARN_DAYS,
        help="warn below this many days (default 30)",
    )
    p.set_defaults(func=cmd_ssl)

    p = sub.add_parser("fim", help="file integrity monitoring")
    fsub = p.add_subparsers(dest="fim_command", required=True)
    keyed = argparse.ArgumentParser(add_help=False)
    keyed.add_argument(
        "--baseline", required=True, help="baseline file; keep it outside the watched folder"
    )
    keyed.add_argument(
        "--key-file", default=str(fim.DEFAULT_KEY_FILE), help="HMAC key (default ~/.secops/fim.key)"
    )

    q = fsub.add_parser(
        "init", parents=[common, keyed], help="hash a folder and save a signed baseline"
    )
    q.add_argument("root")
    q.add_argument(
        "--exclude", action="append", default=[], metavar="GLOB", help="skip matching paths"
    )
    q.add_argument("--force", action="store_true", help="replace an existing baseline")
    q.set_defaults(func=cmd_fim_init)

    q = fsub.add_parser(
        "check", parents=[common, keyed], help="full rescan against the baseline (for a scheduler)"
    )
    q.set_defaults(func=cmd_fim_check)

    q = fsub.add_parser(
        "watch", parents=[common, keyed], help="live events plus a full rescan on a schedule"
    )
    q.add_argument(
        "--rescan", type=int, default=300, help="seconds between full rescans (default 300)"
    )
    q.set_defaults(func=cmd_fim_watch)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        report = args.func(args)
    except (ScopeError, fim.BaselineError, ValueError, OSError) as exc:
        print(f"secops: error: {exc}", file=sys.stderr)
        return ERROR
    if args.command != "fim" or args.fim_command != "watch":
        emit(report, args.json)
    return report.exit_code


if __name__ == "__main__":
    sys.exit(main())

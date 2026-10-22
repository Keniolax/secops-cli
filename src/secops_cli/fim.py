"""File integrity monitoring: a signed baseline, a full rescan, and live events.

  init   hash every file under a folder, sign the result, save it as the baseline
  check  verify the baseline's signature, rescan everything, report differences
  watch  report changes as the operating system announces them, and run a full
         check at start-up and every --rescan seconds

The full check is the source of truth. Events are an early warning: they miss
changes made while the watcher was not running, and the kernel drops them when
its queue overflows. So `watch` rescans on a schedule, and `check` exists so an
outside scheduler (launchd, cron, a systemd timer) can run it even if the
watcher has died.

Nothing here updates the baseline on its own. Accepting a change is a person's
decision: run `init --force`.
"""

from __future__ import annotations

import fnmatch
import hashlib
import hmac
import json
import os
import secrets
import stat
import threading
import time
from collections.abc import Callable, Iterable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .output import ERROR, FINDINGS, OK, Report

FORMAT_VERSION = 1
CHUNK = 1024 * 1024
DEFAULT_KEY_FILE = Path.home() / ".secops" / "fim.key"


class BaselineError(Exception):
    """The baseline is missing, unreadable, or its signature does not verify."""


# --- Signing -------------------------------------------------------------------


def load_or_create_key(path: Path, create: bool) -> bytes:
    """Read the HMAC key. SECOPS_FIM_KEY (hex) wins over the key file."""
    from_env = os.environ.get("SECOPS_FIM_KEY")
    if from_env:
        return bytes.fromhex(from_env)
    if path.exists():
        return bytes.fromhex(path.read_text().strip())
    if not create:
        raise BaselineError(f"no HMAC key: set SECOPS_FIM_KEY or create {path} with `fim init`")
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    key = secrets.token_bytes(32)
    # Create the file with mode 600 from the start, so it is never readable by others.
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(key.hex() + "\n")
    return key


def _canonical(body: dict[str, Any]) -> bytes:
    # Sign a byte-exact form: sorted keys, no spaces. Any reordering or edit changes it.
    return json.dumps(body, sort_keys=True, separators=(",", ":")).encode()


def sign(body: dict[str, Any], key: bytes) -> str:
    return hmac.new(key, _canonical(body), hashlib.sha256).hexdigest()


def verify(body: dict[str, Any], signature: str, key: bytes) -> bool:
    # compare_digest takes the same time whatever the input, so timing leaks nothing.
    return hmac.compare_digest(sign(body, key), signature)


# --- Hashing -------------------------------------------------------------------


def hash_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as f:
        while chunk := f.read(CHUNK):
            digest.update(chunk)
    return digest.hexdigest()


def describe(path: Path) -> dict[str, Any]:
    """What the baseline records about one path. Never follows a symlink."""
    try:
        st = path.lstat()
        if stat.S_ISLNK(st.st_mode):
            return {"type": "symlink", "target": os.readlink(path)}
        return {
            "type": "file",
            "sha256": hash_file(path),
            "size": st.st_size,
            "mode": oct(stat.S_IMODE(st.st_mode)),
        }
    except OSError as exc:
        return {"type": "error", "error": exc.strerror or str(exc)}


def is_excluded(rel: str, patterns: Iterable[str]) -> bool:
    return any(fnmatch.fnmatch(rel, p) or fnmatch.fnmatch(Path(rel).name, p) for p in patterns)


def snapshot(root: Path, exclude: Iterable[str] = ()) -> dict[str, dict[str, Any]]:
    """Describe every file under ROOT, keyed by path relative to ROOT."""
    exclude = list(exclude)
    files: dict[str, dict[str, Any]] = {}
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        here = Path(dirpath)
        dirnames[:] = sorted(
            d for d in dirnames if not is_excluded(str((here / d).relative_to(root)), exclude)
        )
        # os.walk lists symlinks to folders under dirnames; record them as entries too.
        names = list(filenames) + [d for d in dirnames if (here / d).is_symlink()]
        for name in sorted(names):
            rel = str((here / name).relative_to(root))
            if not is_excluded(rel, exclude):
                files[rel] = describe(here / name)
    return files


# --- Baseline ------------------------------------------------------------------


def build_baseline(root: Path, exclude: list[str], key: bytes) -> dict[str, Any]:
    body = {
        "version": FORMAT_VERSION,
        "root": str(root),
        "created": datetime.now(UTC).isoformat(),
        "exclude": exclude,
        "files": snapshot(root, exclude),
    }
    return {"body": body, "hmac": sign(body, key)}


def load_baseline(path: Path, key: bytes) -> dict[str, Any]:
    try:
        doc = json.loads(path.read_text())
        body, signature = doc["body"], doc["hmac"]
    except (OSError, ValueError, KeyError, TypeError) as exc:
        raise BaselineError(f"cannot read baseline {path}: {exc}") from exc
    if not verify(body, signature, key):
        raise BaselineError(
            f"baseline {path} failed its signature check: it was edited, or signed with another key"
        )
    if body.get("version") != FORMAT_VERSION:
        raise BaselineError(
            f"baseline {path} has format {body.get('version')}, expected {FORMAT_VERSION}"
        )
    return body


def diff(old: dict[str, dict], new: dict[str, dict]) -> dict[str, list]:
    """Compare two snapshots. Returns added, removed and modified paths."""
    added = sorted(set(new) - set(old))
    removed = sorted(set(old) - set(new))
    modified = []
    for rel in sorted(set(old) & set(new)):
        if old[rel] != new[rel]:
            fields = sorted(
                k for k in set(old[rel]) | set(new[rel]) if old[rel].get(k) != new[rel].get(k)
            )
            modified.append({"path": rel, "changed": fields})
    return {"added": added, "removed": removed, "modified": modified}


def init(root: Path, baseline: Path, *, key_file: Path, exclude: list[str], force: bool) -> Report:
    root = root.resolve()
    baseline = baseline.resolve()
    if baseline.exists() and not force:
        return Report(
            data={"error": f"{baseline} exists; use --force to replace it"},
            lines=[f"{baseline} exists. Replacing it accepts every change since; use --force."],
            exit_code=ERROR,
        )
    # Never watch the baseline itself, or every save would be a change.
    if baseline.is_relative_to(root):
        exclude = [*exclude, str(baseline.relative_to(root))]
    key = load_or_create_key(key_file, create=True)
    doc = build_baseline(root, exclude, key)
    tmp = baseline.with_suffix(baseline.suffix + ".tmp")
    tmp.write_text(json.dumps(doc, indent=1, sort_keys=True))
    tmp.replace(baseline)  # atomic: a crash never leaves half a baseline
    n = len(doc["body"]["files"])
    return Report(
        data={"baseline": str(baseline), "root": str(root), "files": n},
        lines=[f"baseline of {n} files under {root} saved to {baseline} (signed)"],
    )


def _change_report(body: dict[str, Any], changes: dict[str, list], checked_at: str) -> Report:
    total = sum(len(v) for v in changes.values())
    data = {
        "root": body["root"],
        "baseline_created": body["created"],
        "checked": checked_at,
        **changes,
    }
    lines = [f"{body['root']}: {total} change(s) since baseline of {body['created']}"]
    lines += [f"  ADDED     {p}" for p in changes["added"]]
    lines += [f"  REMOVED   {p}" for p in changes["removed"]]
    lines += [f"  MODIFIED  {m['path']} ({', '.join(m['changed'])})" for m in changes["modified"]]
    return Report(data=data, lines=lines, exit_code=FINDINGS if total else OK)


def check(baseline: Path, *, key_file: Path) -> Report:
    key = load_or_create_key(key_file, create=False)
    body = load_baseline(baseline, key)
    current = snapshot(Path(body["root"]), body["exclude"])
    return _change_report(body, diff(body["files"], current), datetime.now(UTC).isoformat())


# --- Watch ---------------------------------------------------------------------


class Watcher:
    """Turns file events into change reports, without repeating itself.

    The event source is kept apart from this logic so tests can call
    on_path() directly, without real file-system events.
    """

    def __init__(self, body: dict[str, Any], report: Callable[[dict[str, Any]], None]):
        self.body = body
        self.root = Path(body["root"])
        self.report = report
        # The last state reported for each path, so one edit gives one alert, not ten.
        self.reported: dict[str, Any] = {}
        self.lock = threading.Lock()

    def status_of(self, rel: str) -> tuple[str, Any]:
        path = self.root / rel
        expected = self.body["files"].get(rel)
        if not path.exists() and not path.is_symlink():
            return ("removed", None) if expected else ("absent", None)
        now = describe(path)
        if expected is None:
            return "added", now
        return ("unchanged", now) if now == expected else ("modified", now)

    def on_path(self, abs_path: str) -> None:
        # Resolve the folder, not the file: resolving the file would follow a
        # symlink to its target. The folder still needs resolving, because macOS
        # reports /private/var/... for a root given as /var/....
        p = Path(abs_path)
        try:
            rel = str((p.parent.resolve() / p.name).relative_to(self.root))
        except ValueError:
            return
        if rel == "." or is_excluded(rel, self.body["exclude"]) or (self.root / rel).is_dir():
            return
        with self.lock:
            state, now = self.status_of(rel)
            previous = self.reported.get(rel, ("unchanged", self.body["files"].get(rel)))
            if (state, now) == previous or state == "absent":
                return
            self.reported[rel] = (state, now)
            self.report(
                {
                    "event": "change",
                    "time": datetime.now(UTC).isoformat(),
                    "path": rel,
                    "state": state,
                    "now": now,
                    "baseline": self.body["files"].get(rel),
                }
            )


def watch(
    baseline: Path,
    *,
    key_file: Path,
    rescan: int,
    report: Callable[[dict[str, Any]], None],
    stop: threading.Event,
) -> None:
    """Run until STOP is set: events as they come, a full check every RESCAN seconds."""
    from watchdog.events import FileSystemEventHandler
    from watchdog.observers import Observer

    key = load_or_create_key(key_file, create=False)
    body = load_baseline(baseline, key)
    watcher = Watcher(body, report)

    class Handler(FileSystemEventHandler):
        def on_any_event(self, event):
            watcher.on_path(event.src_path)
            if getattr(event, "dest_path", ""):
                watcher.on_path(event.dest_path)

    def full_check(reason: str) -> None:
        result = check(baseline, key_file=key_file)
        report({"event": "rescan", "reason": reason, "exit_code": result.exit_code, **result.data})

    observer = Observer()
    observer.schedule(Handler(), str(watcher.root), recursive=True)
    observer.start()
    try:
        # A check at start catches whatever changed while nothing was watching.
        full_check("start")
        next_scan = time.monotonic() + rescan
        while not stop.wait(timeout=min(1.0, max(0.0, next_scan - time.monotonic()))):
            if time.monotonic() >= next_scan:
                full_check("schedule")
                next_scan = time.monotonic() + rescan
    finally:
        observer.stop()
        observer.join(timeout=5)

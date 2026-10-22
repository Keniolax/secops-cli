"""Tests for file integrity monitoring."""

import json
import os
import threading

import pytest

from secops_cli import fim
from secops_cli.output import ERROR, FINDINGS, OK


@pytest.fixture
def tree(tmp_path):
    root = tmp_path / "watched"
    (root / "etc").mkdir(parents=True)
    (root / "etc" / "passwd").write_text("root:x:0:0\n")
    (root / "notes.txt").write_text("hello\n")
    return root


@pytest.fixture
def key_file(tmp_path):
    return tmp_path / "keys" / "fim.key"


@pytest.fixture
def baseline(tree, tmp_path, key_file):
    path = tmp_path / "watched.baseline.json"
    assert fim.init(tree, path, key_file=key_file, exclude=[], force=False).exit_code == OK
    return path


def test_unchanged_tree_is_ok(baseline, key_file):
    report = fim.check(baseline, key_file=key_file)
    assert report.exit_code == OK
    assert report.data["added"] == report.data["removed"] == report.data["modified"] == []


def test_detects_added_removed_and_modified(tree, baseline, key_file):
    (tree / "etc" / "passwd").write_text("root:x:0:0\nevil:x:0:0\n")
    (tree / "backdoor.sh").write_text("#!/bin/sh\n")
    (tree / "notes.txt").unlink()
    report = fim.check(baseline, key_file=key_file)
    assert report.exit_code == FINDINGS
    assert report.data["added"] == ["backdoor.sh"]
    assert report.data["removed"] == ["notes.txt"]
    assert report.data["modified"] == [{"path": "etc/passwd", "changed": ["sha256", "size"]}]


def test_detects_permission_change_with_same_content(tree, baseline, key_file):
    os.chmod(tree / "notes.txt", 0o600)
    modified = fim.check(baseline, key_file=key_file).data["modified"]
    assert modified == [{"path": "notes.txt", "changed": ["mode"]}]


def test_tampered_baseline_is_refused(baseline, key_file):
    doc = json.loads(baseline.read_text())
    doc["body"]["files"]["etc/passwd"]["sha256"] = "0" * 64
    baseline.write_text(json.dumps(doc))
    with pytest.raises(fim.BaselineError, match="signature"):
        fim.check(baseline, key_file=key_file)


def test_baseline_from_another_key_is_refused(baseline, tmp_path):
    other = tmp_path / "other.key"
    fim.load_or_create_key(other, create=True)
    with pytest.raises(fim.BaselineError, match="signature"):
        fim.check(baseline, key_file=other)


def test_key_file_is_private(baseline, key_file):
    assert key_file.stat().st_mode & 0o777 == 0o600


def test_init_will_not_overwrite_without_force(tree, baseline, key_file):
    assert fim.init(tree, baseline, key_file=key_file, exclude=[], force=False).exit_code == ERROR
    assert fim.init(tree, baseline, key_file=key_file, exclude=[], force=True).exit_code == OK


def test_baseline_inside_the_tree_is_not_watched(tree, key_file):
    inside = tree / "fim.baseline.json"
    fim.init(tree, inside, key_file=key_file, exclude=[], force=False)
    assert fim.check(inside, key_file=key_file).exit_code == OK


def test_symlink_is_recorded_not_followed(tree, tmp_path, key_file):
    outside = tmp_path / "outside.txt"
    outside.write_text("secret\n")
    (tree / "link").symlink_to(outside)
    path = tmp_path / "b.json"
    fim.init(tree, path, key_file=key_file, exclude=[], force=False)
    entry = json.loads(path.read_text())["body"]["files"]["link"]
    assert entry == {"type": "symlink", "target": str(outside)}
    outside.write_text("changed\n")  # the target is outside the tree: not our business
    assert fim.check(path, key_file=key_file).exit_code == OK


def test_exclude_pattern(tree, tmp_path, key_file):
    path = tmp_path / "b.json"
    fim.init(tree, path, key_file=key_file, exclude=["*.txt"], force=False)
    (tree / "notes.txt").write_text("changed\n")
    (tree / "new.txt").write_text("new\n")
    assert fim.check(path, key_file=key_file).exit_code == OK


def test_watcher_reports_each_change_once(tree, baseline, key_file):
    events = []
    body = fim.load_baseline(baseline, fim.load_or_create_key(key_file, create=False))
    watcher = fim.Watcher(body, events.append)
    target = tree / "etc" / "passwd"
    target.write_text("changed\n")
    for _ in range(3):  # editors and the OS often send several events for one save
        watcher.on_path(str(target))
    assert [(e["path"], e["state"]) for e in events] == [("etc/passwd", "modified")]
    target.write_text("root:x:0:0\n")  # put it back
    watcher.on_path(str(target))
    assert [(e["path"], e["state"]) for e in events][-1] == ("etc/passwd", "unchanged")


def test_watch_sees_live_change_and_rescans_at_start(tree, baseline, key_file):
    (tree / "notes.txt").write_text("changed while nobody watched\n")
    events = []
    got_live = threading.Event()

    def report(event):
        events.append(event)
        if event["event"] == "change" and event["path"] == "etc/passwd":
            got_live.set()

    stop = threading.Event()
    thread = threading.Thread(
        target=fim.watch,
        kwargs={
            "baseline": baseline,
            "key_file": key_file,
            "rescan": 3600,
            "report": report,
            "stop": stop,
        },
        daemon=True,
    )
    thread.start()
    try:
        # The start-up rescan must catch the change made before the watcher ran.
        for _ in range(100):
            if any(e["event"] == "rescan" for e in events):
                break
            threading.Event().wait(0.1)
        start = next(e for e in events if e["event"] == "rescan")
        assert start["reason"] == "start"
        assert [m["path"] for m in start["modified"]] == ["notes.txt"]
        # A live edit must arrive as an event, long before the next rescan.
        (tree / "etc" / "passwd").write_text("evil:x:0:0\n")
        assert got_live.wait(timeout=15), "no file event within 15 seconds"
    finally:
        stop.set()
        thread.join(timeout=10)

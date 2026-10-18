"""End-to-end tests for the audit/auth/journald log hunter.

These tests run the real CLI against the real bug trackers with small
limits.  They need network access; run with:

    python3 -m pytest tests/test_hunt_logs_e2e.py -v

The content-classification tests go through the ``python -m
historyhunt.detect_logs`` command so the whole detection path is exercised
the way a user runs it.
"""

import gzip
import os
import subprocess
import sys

import pytest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPTS = os.path.join(REPO_ROOT, "scripts")
HUNT = os.path.join(SCRIPTS, "hunt_logs.py")

_AUDIT = (
    'type=SYSCALL msg=audit(1697040000.123:456): arch=c000003e syscall=59 '
    'success=yes ppid=1234 pid=1235 comm="sudo" exe="/usr/bin/sudo"\n'
    "type=EXECVE msg=audit(1697040000.123:456): argc=3 "
    'a0="sudo" a1="cat" a2="/etc/shadow"\n'
    'type=CWD msg=audit(1697040000.123:456): cwd="/root"\n'
)
_SYSLOG = (
    "Oct 17 10:00:01 myhost sudo:   alice : TTY=pts/0 ; PWD=/home/alice ; "
    "USER=root ; COMMAND=/usr/bin/cat /etc/shadow\n"
    "Oct 17 10:00:02 myhost sshd[1234]: Accepted password for alice from "
    "192.168.1.5 port 51234 ssh2\n"
    "Oct 17 10:01:11 myhost CRON[2233]: (root) CMD (run-parts /etc/cron.hourly)\n"
)

FIXTURES = {
    # auditd records: EXECVE carries the full argv of each executed process.
    "audit": _AUDIT,
    # auth.log / secure / syslog flavor with sudo COMMAND lines.
    "auth": _SYSLOG,
    # journalctl default export: header line plus syslog-style entries.
    "journalctl": (
        "-- Logs begin at Thu 2024-10-17 09:00:00 PDT, "
        "end at Thu 2024-10-17 10:00:00 PDT. --\n" + _SYSLOG
    ),
    # journalctl short-iso timestamps.
    "iso": (
        "2024-10-17T10:00:01.123456+00:00 myhost sudo[111]: "
        "pam_unix(sudo:session): session opened for user root by alice(uid=0)\n"
        "2024-10-17T10:00:02.123456+00:00 myhost sshd[1234]: "
        "Accepted password for alice from 192.168.1.5 port 51234 ssh2\n"
        "2024-10-17T10:01:11.123456+00:00 myhost CRON[2233]: "
        "pam_unix(crond:session): session opened for user root\n"
    ),
    # Binary journald file: LPKSHHRH signature then binary payload.
    "journald": None,  # special-cased below (binary)
    # dmesg: kernel ring buffer, bracketed timestamps, must be rejected.
    "dmesg": (
        "[    0.000000] Linux version 6.8.0 (gcc version 13.2.0)\n"
        "[    0.000001] Command line: BOOT_IMAGE=/vmlinuz root=/dev/sda1\n"
        "[    0.000002] x86/fpu: Supporting XSAVE feature 0x001\n"
    ),
    # A shell history: contains commands but is not a log.
    "history": "#1697040000\nls -la\n#1697040001\nsudo cat /etc/shadow\npwd\n",
    # A Python traceback.
    "traceback": (
        "Traceback (most recent call last):\n"
        '  File "x.py", line 1, in <module>\n'
        "    boom()\n"
        "ValueError: nope\n"
    ),
}


def run_hunt(*args, timeout=120):
    """Run hunt_logs.py with *args* and return the CompletedProcess."""
    return subprocess.run(
        [sys.executable, HUNT, *args],
        capture_output=True,
        text=True,
        timeout=timeout,
    )


@pytest.mark.parametrize(
    "fixture,expected",
    [
        ("audit", "audit"),
        ("auth", "syslog"),
        ("journalctl", "journal"),
        ("iso", "syslog"),
        ("journald", "journald"),
        ("dmesg", "-"),
        ("history", "-"),
        ("traceback", "-"),
    ],
)
def test_detect_command(tmp_path, fixture, expected):
    """The detect_logs module classifies each log flavor, rejects others."""
    path = tmp_path / f"sample-{fixture}"
    if fixture == "journald":
        path.write_bytes(b"LPKSHHRH" + b"\x00\x01\x02" * 100)
    else:
        path.write_text(FIXTURES[fixture])
    result = subprocess.run(
        [sys.executable, "-m", "historyhunt.detect_logs", str(path)],
        capture_output=True,
        text=True,
        env={**os.environ, "PYTHONPATH": SCRIPTS},
    )
    assert f"content={expected}" in result.stdout, result.stdout + result.stderr


def test_detect_command_gzip(tmp_path):
    """A gzipped syslog file is decompressed before classification."""
    path = tmp_path / "syslog.2.gz"
    path.write_bytes(gzip.compress(_SYSLOG.encode()))
    result = subprocess.run(
        [sys.executable, "-m", "historyhunt.detect_logs", str(path)],
        capture_output=True,
        text=True,
        env={**os.environ, "PYTHONPATH": SCRIPTS},
    )
    assert "content=syslog" in result.stdout, result.stdout + result.stderr
    assert "name=target" in result.stdout


def test_redhat_downloads_real_logs(tmp_path):
    """A small Red Hat run downloads real attached audit.log files."""
    out = tmp_path / "dl"
    result = run_hunt(
        "--trackers", "redhat", "--patterns", "audit.log",
        "--max-bugs", "8", "--no-broad", "--out", str(out),
    )
    assert result.returncode == 0, result.stderr[-2000:]
    files = [
        p
        for p in out.rglob("*")
        if p.is_file()
        and p.name not in ("logs_manifest.jsonl", ".loghunt_state.json")
    ]
    assert files, "expected at least one downloaded file: " + result.stdout[-2000:]
    # Layout: <out>/redhat/<issue-id>/<attachment-id>/<filename>
    for path in files:
        rel = path.relative_to(out)
        assert len(rel.parts) == 4, rel
        assert rel.parts[0] == "redhat", rel
    contents = b"".join(p.read_bytes() for p in files)
    assert b"msg=audit(" in contents, "no audit records in downloaded files"
    manifest = (out / "logs_manifest.jsonl").read_text()
    assert '"tracker": "redhat"' in manifest
    assert '"kind": "audit"' in manifest


def test_resume_skips_existing_files(tmp_path):
    """A second identical run downloads nothing new (files and state reused)."""
    out = tmp_path / "dl"
    args = (
        "--trackers", "redhat", "--patterns", "audit.log",
        "--max-bugs", "8", "--no-broad", "--out", str(out),
    )
    first = run_hunt(*args)
    assert first.returncode == 0, first.stderr[-2000:]
    manifest_path = out / "logs_manifest.jsonl"
    manifest_before = manifest_path.read_text()
    mtimes_before = {p: p.stat().st_mtime for p in out.rglob("*") if p.is_file()}
    second = run_hunt(*args)
    assert second.returncode == 0, second.stderr[-2000:]
    assert manifest_path.read_text() == manifest_before, "manifest grew on resume"
    assert "0 downloaded" in second.stdout
    for path, mtime in mtimes_before.items():
        assert path.stat().st_mtime == mtime, f"{path} was rewritten"


def test_dry_run_downloads_nothing(tmp_path):
    """--dry-run lists candidates but writes no files."""
    out = tmp_path / "dl"
    result = run_hunt(
        "--trackers", "redhat", "--patterns", "audit.log",
        "--max-bugs", "3", "--no-broad", "--dry-run", "--out", str(out),
    )
    assert result.returncode == 0, result.stderr[-2000:]
    assert "[dry-run]" in result.stdout
    files = [
        p
        for p in out.rglob("*")
        if p.is_file() and p.name not in (".loghunt_state.json",)
    ]
    assert not files


def test_alpine_gitlab_flow(tmp_path):
    """Alpine's GitLab adapter searches and completes without errors."""
    out = tmp_path / "dl"
    result = run_hunt(
        "--trackers", "alpine", "--max-bugs", "2", "--dry-run", "--out", str(out)
    )
    assert result.returncode == 0, result.stderr[-2000:]
    assert "[alpine] done" in result.stdout


def test_unknown_tracker_rejected(tmp_path):
    """An unknown tracker name exits with usage error code 2."""
    result = run_hunt("--trackers", "nosuchtracker", "--out", str(tmp_path))
    assert result.returncode == 2
    assert "unknown tracker" in result.stderr

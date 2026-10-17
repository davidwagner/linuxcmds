"""End-to-end tests for the history hunter.

These tests run the real CLI against the real bug trackers with small
limits.  They need network access and are not fast; run with:

    python3 -m pytest tests/test_hunt_e2e.py -v

The content-classification tests go through the ``python -m
historyhunt.detect`` command so the whole detection path is exercised the
way a user runs it.
"""

import os
import subprocess
import sys

import pytest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPTS = os.path.join(REPO_ROOT, "scripts")
HUNT = os.path.join(SCRIPTS, "hunt_history.py")

FIXTURES = {
    "bash": "cd ~/projects\nls -la\ngit status\nsudo apt install vim\nvim foo.txt\nexit\n",
    "bash_ts": "#1697040000\ncd /tmp\n#1697040100\nls -la\n#1697040200\nmake install\n",
    # Another timestamped-history format: "#+<epoch>" lines between commands
    # (found in the wild on Red Hat's Bugzilla).
    "hash_plus": "#+1127127449\npsg dhc\n#+1127127575\nip tun list\n"
    "#+1127128069\nip history | grep nql\n#+1127191963\n"
    "rpm -q selinux-policy-targeted\n#+1127212712\ncat folders.txt\n"
    "#+1127212737\nlynx bridging.shtml.html\n#+1127308489\nls -la\n"
    "#+1127308500\nexit\n",
    "zsh": ": 1697040000:0;cd /tmp\n: 1697040100:2;make -j4\n: 1697040200:0;git push\n",
    "fish": "- cmd: cd /tmp\n  when: 1697040000\n- cmd: make -j4\n  when: 1697040100\n"
    "- cmd: git push\n  when: 1697040200\n- cmd: ls\n  when: 1697040300\n",
    "apt": "Start-Date: 2024-01-01  10:00:00\nCommandline: apt-get install vim\n"
    "Install: vim:amd64 (2.9.0)\nEnd-Date: 2024-01-01  10:01:00\n",
    "nginx": "server {\n    listen 80;\n    server_name example.com;\n"
    "    root /var/www/html;\n    index index.html;\n    location / {\n"
    "        try_files $uri $uri/ =404;\n    }\n}\n",
    # An apparmor profile: full of absolute paths, must not look like a
    # shell history (this was a real false positive found in testing).
    "apparmor": "/usr/sbin/mysqld {\n  capability dac_override,\n"
    "  network tcp,\n  /etc/mysql/** r,\n  /var/lib/mysql/** rwk,\n"
    "  /usr/sbin/mysqld mr,\n  ptrace,\n  unix,\n  signal,\n}\n",
    # Environment dump (Launchpad's ProcEnviron.txt): all assignments.
    "envdump": "LANGUAGE=en_US:en\nLC_TIME=en_IN.UTF-8\nTERM=xterm\n"
    "PATH=(custom, user)\nSHELL=/bin/bash\nLC_ADDRESS=en_IN.UTF-8\n",
    # terminfo source: lines of capability=value pairs.
    "terminfo": "#\tReconstructed via infocmp from file: /lib/terminfo/x/xterm\n"
    "xterm-256color|xterm with 256 colors,\n"
    "\tam, bce, ccc, km, mc5i, mir, msgr, npc, xenl,\n"
    "\tcolors#256, cols#80, it#8, lines#24, pairs#32767,\n"
    "\tbel=^G, blink=\\E[5m, bold=\\E[1m, cbt=\\E[Z,\n",
    # A shell script, not a history.
    "script": "#!/bin/sh\n# Set the message.\nset -e\nset -x\numask 0027\n"
    "if [ -f /etc/default/foo ]; then\n  . /etc/default/foo\nfi\n",
}


def run_hunt(*args, timeout=600):
    """Run hunt_history.py with *args* and return the CompletedProcess."""
    return subprocess.run(
        [sys.executable, HUNT, *args],
        capture_output=True,
        text=True,
        timeout=timeout,
    )


@pytest.mark.parametrize(
    "fixture,expected",
    [
        ("bash", "sh"),
        ("bash_ts", "bash"),
        ("hash_plus", "sh"),
        ("zsh", "zsh"),
        ("fish", "fish"),
        ("apt", "-"),
        ("nginx", "-"),
        ("apparmor", "-"),
        ("envdump", "-"),
        ("terminfo", "-"),
        ("script", "-"),
    ],
)
def test_detect_command(tmp_path, fixture, expected):
    """The detect module classifies each history flavor and rejects configs."""
    path = tmp_path / f"sample-{fixture}"
    path.write_text(FIXTURES[fixture])
    result = subprocess.run(
        [sys.executable, "-m", "historyhunt.detect", str(path)],
        capture_output=True,
        text=True,
        env={**os.environ, "PYTHONPATH": SCRIPTS},
    )
    assert f"content={expected}" in result.stdout, result.stdout + result.stderr


def test_redhat_downloads_real_history(tmp_path):
    """A small Red Hat run downloads a real attached .bash_history."""
    out = tmp_path / "dl"
    result = run_hunt(
        "--trackers", "redhat", "--max-bugs", "10", "--no-broad", "--out", str(out)
    )
    assert result.returncode == 0, result.stderr[-2000:]
    files = [
        p
        for p in out.rglob("*")
        if p.is_file() and p.name not in ("manifest.jsonl", ".hunt_state.json")
    ]
    assert files, "expected at least one downloaded file"
    # Layout: <out>/redhat/<issue-id>/<attachment-id>/<filename>
    for path in files:
        rel = path.relative_to(out)
        assert len(rel.parts) == 4, rel
        assert rel.parts[0] == "redhat", rel
    contents = b"".join(p.read_bytes() for p in files)
    assert b"\n" in contents
    manifest = (out / "manifest.jsonl").read_text()
    assert '"tracker": "redhat"' in manifest


def test_resume_skips_existing_files(tmp_path):
    """A second identical run downloads nothing new (files and state reused)."""
    out = tmp_path / "dl"
    args = ("--trackers", "redhat", "--max-bugs", "10", "--no-broad", "--out", str(out))
    first = run_hunt(*args)
    assert first.returncode == 0, first.stderr[-2000:]
    manifest_path = out / "manifest.jsonl"
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
        "--trackers", "redhat", "--max-bugs", "3", "--no-broad",
        "--dry-run", "--out", str(out),
    )
    assert result.returncode == 0, result.stderr[-2000:]
    files = [
        p
        for p in out.rglob("*")
        if p.is_file() and p.name not in (".hunt_state.json",)
    ]
    assert not files


def test_ubuntu_launchpad_flow(tmp_path):
    """Ubuntu's Launchpad adapter scans bugs and sniff-rejects non-history."""
    out = tmp_path / "dl"
    result = run_hunt("--trackers", "ubuntu", "--max-bugs", "2", "--out", str(out))
    assert result.returncode == 0, result.stderr[-2000:]
    assert (out / ".hunt_state.json").exists()


def test_unknown_tracker_rejected(tmp_path):
    """An unknown tracker name exits with usage error code 2."""
    result = run_hunt("--trackers", "nosuchtracker", "--out", str(tmp_path))
    assert result.returncode == 2
    assert "unknown tracker" in result.stderr

"""Recognize audit/auth/journald log files by filename and by content.

Why these files: they record processes executed *with their arguments*.

- ``/var/log/audit/audit.log`` (auditd) has one record group per audited
  syscall; its ``EXECVE`` records carry the full argv (``a0="sudo"
  a1="cat" ...``) and ``PROCTITLE`` carries it again hex-encoded.
- ``auth.log`` (Debian/Ubuntu) and ``secure`` (RHEL/Fedora/SUSE) record
  every sudo invocation with its command line (``COMMAND=/usr/bin/foo
  --bar``), plus sshd/logind session activity.
- ``syslog`` and journald exports (``journalctl`` output, ``journal*``
  files) contain the same sudo/sshd records; binary ``*.journal`` files
  are journald's on-disk format and can be read with ``journalctl
  --file``.

Two ways a file is spotted, mirroring ``detect.py``:

1. By name.  :func:`is_log_filename` matches ``audit.log`` and its
   rotations, ``auth.log``, ``secure``, ``syslog``, sudo logs, journalctl
   exports and ``*.journal`` files, after stripping the upload suffixes
   people add (``.txt``, ``.gz``, `` (1)``, ...).

2. By content.  Attachments with generic or missing names
   (``output.txt``, unnamed mail parts) are content-checked by
   :func:`classify_log`, which recognizes the audit record format, syslog
   lines (traditional and ISO-8601), journalctl exports and the binary
   journald file magic.
"""

import re
import zlib

from .common import Profile

# Substrings for Bugzilla's attachment-filename search (high precision).
FILENAME_PATTERNS = [
    "audit.log",
    "auditlog",
    "auth.log",
    "authlog",
    "secure",
    "syslog",
    "sudo",
    "journalctl",
]

# Noisier filename substring, searched unless --no-broad is given:
# "journal" matches ~6x more bugs than "journalctl" alone (~4k on Red
# Hat).  "/var/log/messages" (the RHEL-family equivalent of syslog) was
# considered and dropped: ~36k matching bugs on Red Hat makes a full scan
# impractical, and syslog-format files still surface via "syslog" and the
# content check on generic names.
BROAD_PATTERNS = ["journal"]

# Terms for trackers with full-text search only (Launchpad, GitHub,
# GitLab, Mantis, the Debian mail archive).
TEXT_PATTERNS = [
    "audit.log",
    "auth.log",
    "secure.log",
    "syslog",
    "journalctl",
    "system.journal",
]

# Suffixes people append when uploading a log file (or that rotation adds).
_SUFFIX_RE = re.compile(
    r"(?:\s*\(\d+\)|~|\.(?:txt|text|out|gz|bz2|xz|zip|zst|lz4|old|bak|orig"
    r"|save|sav|copy|backup|new|redacted|anon|anonymi[sz]ed|clean|\d{1,4}))"
    r"+$"
)

# Config/source/document files whose names could otherwise resemble a target.
_EXCLUDE_RE = re.compile(
    r"\.(?:conf|cfg|ini|rules|service|socket|mount|timer|py|pyc|service"
    r"|pdf|docx?|odt|png|jpe?g|gif|svg|html?)$"
)

_TARGET_RES = [
    # audit.log, auditlog, audit_log, audit.log.4, ...
    re.compile(r"^audit[._-]?logs?([._-]\d+)*$"),
    # auth.log, authlog, auth.log.1, ...
    re.compile(r"^auth[._-]?logs?([._-]\d+)*$"),
    # secure, secure.1, secure-20240101, secure.log (not secure-boot...)
    re.compile(r"^secure([._-](?:log|\d+))*$"),
    # syslog, syslog.1, ...
    re.compile(r"^syslogs?([._-]\d+)*$"),
    # sudo, sudo.log, sudo_log, sudo-history (not sudoers)
    re.compile(r"^sudo([._-](?:logs?|history|commands?|\d+))*$"),
    # journal, journalctl, journalctl-errors, JournalctlErrors, ...
    re.compile(r"^journal"),
    # system.journal, user-1000.journal, ...
    re.compile(r"\.journal$"),
    # systemd-journal, systemd_journal, ...
    re.compile(r"^systemd[._-]?journal"),
]

# Ambiguous names that need a content check before the file is kept.
# "messages" is here (not in _TARGET_RES) so that e.g. "messages.txt"
# files that are not actually syslog-format get rejected by classify_log.
_GENERIC_RE = re.compile(
    r"^\.?(logs?|output|out|errors?|messages|debug|trace)([._-]\d+)*$"
)


def _stem(name):
    """Reduce a filename to its core basename for matching.

    Strips directory parts and any number of trailing upload/rotation
    suffixes, so ``/tmp/auth.log (1).txt`` becomes ``auth.log``.  Unlike
    the shell-history stemmer this does NOT strip ``.log``: it is part of
    the target names.
    """
    base = name.strip().replace("\\", "/").rsplit("/", 1)[-1].lower()
    prev = None
    while prev != base:
        prev = base
        base = _SUFFIX_RE.sub("", base)
    return base


def is_log_filename(name):
    """Return True if *name* looks like an audit/auth/journald log file.

    Examples that match: ``audit.log``, ``audit.log.1``, ``auth.log.gz``,
    ``secure``, ``secure-20240101``, ``syslog``, ``sudo.log``,
    ``Journalctl.txt``, ``JournalctlErrors.txt``, ``system.journal``.
    Examples that do not: ``sudoers``, ``secure-boot.log``,
    ``audit.rules``, ``journald.conf``.
    """
    if not name:
        return False
    stem = _stem(name)
    if _EXCLUDE_RE.search(stem):
        return False
    return any(rx.search(stem) for rx in _TARGET_RES)


def is_generic_log_name(name):
    """Return True for ambiguous names like ``log``, ``output.txt``.

    These need :func:`classify_log` to confirm the content before keeping.
    """
    return bool(name) and bool(_GENERIC_RE.match(_stem(name)))


# --- content classification -------------------------------------------------

# First 8 bytes of every journald journal file (see systemd's
# src/libsystemd/sd-journal/journal-def.h, HEADER_SIGNATURE).
_JOURNALD_MAGIC = b"LPKSHHRH"

# auditd record: "type=SYSCALL msg=audit(1697040000.123:456): ..."
_AUDIT_RE = re.compile(r"^type=[A-Z_]+ msg=audit\(\d+\.\d+:\d+\):", re.M)

# Traditional syslog: "Oct 17 10:00:01 myhost sudo[1234]: ..."
_SYSLOG_RE = re.compile(
    r"^[A-Z][a-z]{2} [ 0-9]\d \d{2}:\d{2}:\d{2} [^\s:]+ [^\s:\[]+(?:\[\d+\])?: ",
    re.M,
)

# journalctl short-iso / rsyslog high precision:
# "2024-10-17T10:00:01.123456+00:00 myhost sudo[1234]: ..."
_ISO_SYSLOG_RE = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:[.,]\d+)?(?:Z|[+-]\d{2}:?\d{2})"
    r" [^\s:]+ [^\s:\[]+(?:\[\d+\])?: ",
    re.M,
)

# journalctl default output starts with "-- Logs begin at ..." and marks
# boots with "-- Boot <id> --".
_JOURNAL_MARKER_RE = re.compile(
    r"^-- (?:Logs begin at|Journal starts at|Boot [0-9a-f]{8})", re.M
)


def _gunzip_prefix(data):
    """Decompress as much of a gzip stream as *data* allows.

    Sniffed downloads are capped, so the stream is usually truncated;
    zlib returns everything up to the truncation point instead of
    raising.  Returns b"" when the data is not a valid gzip stream.
    """
    try:
        return zlib.decompressobj(16 + zlib.MAX_WBITS).decompress(
            data, 2 * 1024 * 1024
        )
    except zlib.error:
        return b""


def classify_log(data):
    """Classify *data* as audit/auth/journald log content.

    Returns one of ``"audit"`` (auditd records), ``"syslog"`` (traditional
    or ISO syslog lines: auth.log, secure, syslog, messages), ``"journal"``
    (journalctl text or JSON export) or ``"journald"`` (binary journal
    file); ``None`` when the data looks like something else.  Gzipped
    input is transparently decompressed.
    """
    if data[:8] == _JOURNALD_MAGIC:
        return "journald"
    if data[:2] == b"\x1f\x8b":
        data = _gunzip_prefix(data)
        if not data:
            return None
    text = data[:262144].decode("utf-8", "replace")
    lines = [ln for ln in text.splitlines() if ln.strip()]
    if len(lines) < 3:
        return None
    if len(_AUDIT_RE.findall(text)) >= 2:
        return "audit"
    if _JOURNAL_MARKER_RE.search(text):
        return "journal"
    # journalctl -o verbose / -o export / -o json carry these fields.
    if text.count("__REALTIME_TIMESTAMP") >= 2 and "__CURSOR" in text:
        return "journal"
    syslogish = len(_SYSLOG_RE.findall(text)) + len(_ISO_SYSLOG_RE.findall(text))
    if syslogish >= 3 and syslogish / len(lines) >= 0.4:
        return "syslog"
    return None


def logs_profile():
    """Build the audit/auth/journald hunting profile."""
    return Profile(
        name="logs",
        state_filename=".loghunt_state.json",
        manifest_filename="logs_manifest.jsonl",
        filename_patterns=FILENAME_PATTERNS,
        broad_patterns=BROAD_PATTERNS,
        text_patterns=TEXT_PATTERNS,
        is_target_filename=is_log_filename,
        is_generic_name=is_generic_log_name,
        classify=classify_log,
    )


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("usage: python -m historyhunt.detect_logs FILE...", file=sys.stderr)
        sys.exit(2)
    status = 0
    for path in sys.argv[1:]:
        with open(path, "rb") as fh:
            kind = classify_log(fh.read())
        name_hit = is_log_filename(path)
        generic_hit = is_generic_log_name(path)
        print(
            f"{path}: content={kind or '-'} "
            f"name={'target' if name_hit else 'generic' if generic_hit else '-'}"
        )
        if kind is None and not name_hit:
            status = 1
    sys.exit(status)

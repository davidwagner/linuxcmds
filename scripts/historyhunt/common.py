"""Shared plumbing: HTTP with retries, resumable downloads, progress, state.

Everything here is standard-library only so the scripts run on any machine
with Python 3.9+ and no packages to install.

What a hunt looks for (search patterns, filename tests, content classifier)
is kept separate from how trackers are searched: a :class:`Profile` bundles
the former and is handed to every tracker through :class:`Config`.  The
profiles live in ``historyhunt.detect`` (shell history) and
``historyhunt.detect_logs`` (audit/auth/journald logs).
"""

import json
import os
import re
import sys
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Callable, List, Optional

USER_AGENT = "kiss-linuxcmds/1.0 (public bug-tracker research; stdlib urllib)"


class FetchError(Exception):
    """A URL could not be fetched after all retries."""


@dataclass
class Response:
    """Result of an HTTP GET: status code, response headers, body bytes."""

    status: int
    headers: dict
    body: bytes


class HttpClient:
    """Small HTTP client with politeness delay, retries and backoff.

    Retries on connection errors, HTTP 429 and 5xx.  Honors ``Retry-After``
    and GitHub's ``X-RateLimit-Reset``.  A minimum delay between requests is
    enforced so we do not hammer the trackers.
    """

    def __init__(self, delay=0.3, retries=4, timeout=60, verbose=False):
        """Configure the client: delay in seconds between requests, number of
        retries per request, per-request socket timeout, and a verbose flag
        that prints every URL fetched to stderr."""
        self.delay = delay
        self.retries = retries
        self.timeout = timeout
        self.verbose = verbose
        self._last_request = 0.0

    def _polite_wait(self):
        gap = time.time() - self._last_request
        if gap < self.delay:
            time.sleep(self.delay - gap)
        self._last_request = time.time()

    def _backoff(self, attempt, headers):
        retry_after = headers.get("Retry-After") or headers.get("retry-after")
        if retry_after:
            try:
                return min(float(retry_after), 120.0)
            except ValueError:
                pass
        remaining = headers.get("x-ratelimit-remaining")
        reset = headers.get("x-ratelimit-reset")
        if remaining == "0" and reset:
            try:
                return min(max(float(reset) - time.time(), 1.0), 90.0)
            except ValueError:
                pass
        return min(2.0**attempt, 60.0)

    def open(self, url, headers=None, max_bytes=None):
        """GET *url* and return a :class:`Response`.

        *max_bytes* caps how much of the body is read (raises FetchError when
        the body is larger).  Raises FetchError on 4xx (other than retriable
        429) and after exhausting retries.
        """
        hdrs = {"User-Agent": USER_AGENT, "Accept-Encoding": "identity"}
        if headers:
            hdrs.update(headers)
        body_cap = max_bytes if max_bytes is not None else 64 * 1024 * 1024
        last_error = None
        for attempt in range(self.retries):
            self._polite_wait()
            if self.verbose:
                print(f"  GET {url}", file=sys.stderr)
            try:
                with urllib.request.urlopen(
                    urllib.request.Request(url, headers=hdrs), timeout=self.timeout
                ) as resp:
                    body = resp.read(body_cap + 1)
                    if len(body) > body_cap:
                        raise FetchError(f"response too large (> {body_cap} bytes): {url}")
                    return Response(resp.status, dict(resp.headers), body)
            except urllib.error.HTTPError as exc:
                last_error = exc
                if exc.code == 429 or exc.code >= 500:
                    time.sleep(self._backoff(attempt, dict(exc.headers or {})))
                    continue
                raise FetchError(f"HTTP {exc.code} for {url}") from exc
            except (urllib.error.URLError, TimeoutError, ConnectionError) as exc:
                last_error = exc
                time.sleep(min(2.0**attempt, 60.0))
        raise FetchError(f"giving up on {url}: {last_error}")

    def get_json(self, url, headers=None):
        """GET *url* and parse the body as JSON."""
        resp = self.open(url, headers=headers)
        try:
            return json.loads(resp.body.decode("utf-8", "replace"))
        except json.JSONDecodeError as exc:
            raise FetchError(f"non-JSON response from {url}") from exc


class Progress:
    """A single-line progress display written to stderr.

    ``log()`` prints a message on its own line above the progress line; the
    progress line itself is redrawn in place on terminals.
    """

    def __init__(self, label, total):
        """Start a progress line called *label* expecting *total* work items
        (None when the total is unknown)."""
        self.label = label
        self.total = total
        self.done = 0
        self.files = 0
        self.bytes = 0
        self._t0 = time.time()
        self._tty = sys.stderr.isatty()
        self._render()

    def _line(self):
        elapsed = time.strftime("%H:%M:%S", time.gmtime(time.time() - self._t0))
        total = "?" if self.total is None else str(self.total)
        mib = self.bytes / (1024 * 1024)
        return (
            f"{self.label}: {self.done}/{total} issues checked | "
            f"{self.files} files, {mib:.1f} MiB | {elapsed} elapsed"
        )

    def _render(self):
        line = self._line()
        if self._tty:
            sys.stderr.write("\r" + line.ljust(100)[:100])
            sys.stderr.flush()
        elif self.done % 25 == 0:
            print(line, file=sys.stderr)

    def advance(self, files=0, nbytes=0):
        """Mark one work item done; optionally credit downloaded files/bytes."""
        self.done += 1
        self.files += files
        self.bytes += nbytes
        self._render()

    def log(self, msg):
        """Print *msg* above the progress line without losing progress state."""
        if self._tty:
            sys.stderr.write("\r" + " " * 100 + "\r")
        print(msg, file=sys.stderr)
        if self._tty:
            self._render()

    def finish(self):
        """Close the progress line and print a final summary."""
        if self._tty:
            sys.stderr.write("\r" + " " * 100 + "\r")
        print(self._line(), file=sys.stderr)


class State:
    """Persistent crawl state so interrupted runs resume cheaply.

    Stored as JSON with one list of finished issue ids per tracker.  Finished
    downloads are detected by the presence of the destination file itself;
    this file only avoids re-scanning issues that produced nothing new.
    """

    def __init__(self, path):
        """Load state from *path* (created on first save if missing)."""
        self.path = path
        self.enabled = True  # dry runs set this False so nothing is recorded
        try:
            with open(path, encoding="utf-8") as fh:
                self._data = json.load(fh)
        except (OSError, json.JSONDecodeError):
            self._data = {"issues_done": {}}

    def is_done(self, tracker, issue_id):
        """Return True when *issue_id* was fully processed for *tracker*."""
        return str(issue_id) in self._data["issues_done"].get(tracker, [])

    def mark_done(self, tracker, issue_id):
        """Record *issue_id* as processed for *tracker* and save."""
        if not self.enabled:
            return
        done = self._data["issues_done"].setdefault(tracker, [])
        sid = str(issue_id)
        if sid not in done:
            done.append(sid)
            self.save()

    def save(self):
        """Atomically write the state file."""
        tmp = self.path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(self._data, fh)
        os.replace(tmp, self.path)


_UNSAFE_CHARS_RE = re.compile(r"[^\w.\-~ +]", re.U)


def sanitize(name, fallback="x"):
    """Make *name* safe to use as one path component."""
    name = name.strip().replace("/", "_").replace("\\", "_")
    name = _UNSAFE_CHARS_RE.sub("_", name).strip(". ")
    return (name or fallback)[:120]


def attachment_dest(out_dir, tracker, issue_id, attachment_id, filename):
    """Build downloaded/<tracker>/<issue-id>/<attachment-id>/<filename>."""
    return os.path.join(
        out_dir,
        sanitize(tracker),
        sanitize(str(issue_id)),
        sanitize(str(attachment_id)),
        sanitize(filename, fallback="attachment.bin"),
    )


def download_to(http, url, dest, max_size):
    """Download *url* to *dest*, resuming a partial ``.part`` file.

    Returns ``(status, size)`` where status is "downloaded", "resumed" or
    "skipped" (destination already complete).  Partial files are kept as
    ``dest + ".part"`` and resumed with an HTTP Range request when the server
    supports it.
    """
    if os.path.exists(dest):
        return "skipped", os.path.getsize(dest)
    os.makedirs(os.path.dirname(dest), exist_ok=True)
    part = dest + ".part"
    have = os.path.getsize(part) if os.path.exists(part) else 0
    headers = {"Range": f"bytes={have}-"} if have else None
    status = "resumed" if have else "downloaded"
    last_error = None
    for attempt in range(http.retries):
        http._polite_wait()
        if http.verbose:
            print(f"  GET {url} (offset {have})", file=sys.stderr)
        try:
            req_headers = {"User-Agent": USER_AGENT, "Accept-Encoding": "identity"}
            if headers:
                req_headers.update(headers)
            req = urllib.request.Request(url, headers=req_headers)
            with urllib.request.urlopen(req, timeout=http.timeout) as resp:
                mode = "ab" if (have and resp.status == 206) else "wb"
                if mode == "wb":
                    have = 0
                with open(part, mode) as out:
                    while True:
                        chunk = resp.read(65536)
                        if not chunk:
                            break
                        out.write(chunk)
                        have += len(chunk)
                        if have > max_size:
                            raise FetchError(f"file too large (> {max_size} bytes): {url}")
            os.replace(part, dest)
            return status, have
        except urllib.error.HTTPError as exc:
            if exc.code == 416:  # range not satisfiable: restart cleanly
                if os.path.exists(part):
                    os.remove(part)
                have = 0
                headers = None
                continue
            if exc.code == 429 or exc.code >= 500:
                time.sleep(min(2.0**attempt, 60.0))
                last_error = exc
                continue
            raise FetchError(f"HTTP {exc.code} for {url}") from exc
        except (urllib.error.URLError, TimeoutError, ConnectionError) as exc:
            last_error = exc
            time.sleep(min(2.0**attempt, 60.0))
    raise FetchError(f"giving up on {url}: {last_error}")


@dataclass
class Candidate:
    """One attachment that might be a file the hunt is looking for.

    When *sniff* is True the filename is generic or missing and the content
    must be classified before keeping the file; False means the filename
    already identifies it as wanted.
    """

    tracker: str
    issue_id: str
    attachment_id: str
    filename: str
    url: str
    sniff: bool = False
    size: int = 0
    issue_url: str = ""
    extra: dict = field(default_factory=dict)


@dataclass
class Profile:
    """What one hunt looks for: search patterns, filename tests, classifier.

    - *filename_patterns*: substrings for Bugzilla's attachment-filename
      search (high precision).
    - *broad_patterns*: noisier substrings for the same search, skipped
      with ``--no-broad``.
    - *text_patterns*: search terms for trackers that only offer full-text
      search (Launchpad, GitHub, GitLab, Mantis, the Debian mail archive).
    - *is_target_filename*: filename alone identifies a wanted file.
    - *is_generic_name*: filename is ambiguous; keep only if *classify*
      recognizes the content.
    - *classify*: bytes -> short label ("audit", "syslog", ...) or None.
    """

    name: str
    state_filename: str
    manifest_filename: str
    filename_patterns: List[str]
    broad_patterns: List[str]
    text_patterns: List[str]
    is_target_filename: Callable[[str], bool]
    is_generic_name: Callable[[str], bool]
    classify: Callable[[bytes], Optional[str]]


@dataclass
class Config:
    """Run configuration shared by all trackers."""

    out_dir: str
    profile: Profile
    max_bugs: int = 0  # 0 = unlimited
    broad: bool = True  # also search the profile's broad patterns
    comments_search: bool = False  # also search issue text/comments
    delay: float = 0.3
    max_size: int = 50 * 1024 * 1024
    sniff_size: int = 10 * 1024 * 1024
    dry_run: bool = False
    verbose: bool = False
    github_token: str = ""
    # Bugzilla instance name -> API key (sent as Authorization: Bearer).
    bugzilla_api_keys: dict = field(default_factory=dict)

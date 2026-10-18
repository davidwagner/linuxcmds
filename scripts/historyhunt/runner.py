"""Shared hunt driver: argument parsing, downloading, manifest, resume.

Both hunt_history.py (shell history) and hunt_logs.py (audit/auth/journald
logs) are thin wrappers around :func:`run`, differing only in the
:class:`historyhunt.common.Profile` they pass in.
"""

import argparse
import base64
import json
import os
import sys
import time
from collections import Counter

from .common import (
    Config,
    FetchError,
    HttpClient,
    State,
    attachment_dest,
    download_to,
)
from .trackers import TRACKER_NAMES, build_tracker


def parse_args(argv, prog, description):
    """Parse command-line arguments for a hunt script called *prog*."""
    parser = argparse.ArgumentParser(
        prog=prog,
        description=description,
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""\
examples:
    python3 scripts/{prog}                      # everything
    python3 scripts/{prog} --trackers redhat,ubuntu --max-bugs 10
    python3 scripts/{prog} --trackers mint --dry-run
    python3 scripts/{prog} --trackers redhat --patterns audit.log
""",
    )
    parser.add_argument(
        "--trackers",
        default=",".join(TRACKER_NAMES),
        help="comma-separated subset of: " + ",".join(TRACKER_NAMES),
    )
    parser.add_argument(
        "--out",
        default=None,
        help="output directory (default: <repo>/downloaded)",
    )
    parser.add_argument(
        "--max-bugs",
        type=int,
        default=0,
        help="cap issues scanned per tracker (0 = no cap)",
    )
    parser.add_argument(
        "--patterns",
        default="",
        help="comma-separated search patterns replacing the profile's own",
    )
    parser.add_argument(
        "--no-broad",
        action="store_true",
        help="skip the profile's noisier broad patterns on Bugzilla",
    )
    parser.add_argument(
        "--comments-search",
        action="store_true",
        help="also search Bugzilla comments for the text patterns (slow)",
    )
    parser.add_argument(
        "--delay",
        type=float,
        default=0.3,
        help="minimum seconds between HTTP requests (default: 0.3)",
    )
    parser.add_argument(
        "--max-size",
        type=int,
        default=50,
        help="skip downloads larger than this many MiB (default: 50)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="list candidate attachments without downloading",
    )
    parser.add_argument("-v", "--verbose", action="store_true")
    return parser.parse_args(argv)


class Runner:
    """Drive the trackers, download candidates and record a manifest."""

    def __init__(self, config):
        """Create the HTTP client, state store and manifest file."""
        self.cfg = config
        self.profile = config.profile
        self.http = HttpClient(delay=config.delay, verbose=config.verbose)
        self.state = State(os.path.join(config.out_dir, self.profile.state_filename))
        self.state.enabled = not config.dry_run
        self.manifest_path = os.path.join(config.out_dir, self.profile.manifest_filename)
        self.counts = Counter()

    def _record(self, cand, dest, kind, size):
        entry = {
            "path": os.path.relpath(dest, self.cfg.out_dir),
            "tracker": cand.tracker,
            "issue_id": cand.issue_id,
            "attachment_id": cand.attachment_id,
            "filename": os.path.basename(dest),
            "issue_url": cand.issue_url,
            "url": cand.url,
            "kind": kind,
            "size": size,
        }
        with open(self.manifest_path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry) + "\n")

    def _fetch_bytes(self, cand):
        """Fetch a candidate's raw bytes.

        Candidates marked ``rest_b64`` come from Bugzilla's REST attachment
        endpoint (JSON with a base64 ``data`` field); everything else is a
        plain GET capped at the sniff size.
        """
        headers = cand.extra.get("headers") or None
        if cand.extra.get("rest_b64"):
            data = self.http.get_json(cand.url, headers=headers)
            att = data.get("attachments", {}).get(cand.attachment_id, {})
            if att.get("size", 0) > self.cfg.max_size:
                raise FetchError(f"attachment too large: {cand.url}")
            try:
                return base64.b64decode(att.get("data", ""))
            except (ValueError, TypeError) as exc:
                raise FetchError(f"bad base64 from {cand.url}") from exc
        return self.http.open(
            cand.url, headers=headers, max_bytes=self.cfg.sniff_size
        ).body

    @staticmethod
    def _is_bot_challenge(head):
        """True when *head* is an anti-bot HTML page, not a real download."""
        return b"not a bot" in head or b"xess.min.css" in head

    def _write(self, dest, data):
        """Atomically write *data* to *dest* (via a .part temp file)."""
        os.makedirs(os.path.dirname(dest), exist_ok=True)
        tmp = dest + ".part"
        with open(tmp, "wb") as fh:
            fh.write(data)
        os.replace(tmp, dest)

    def process(self, cand, log):
        """Handle one candidate attachment.

        *log* is the tracker's progress-line logger.  Returns the number of
        bytes newly stored (0 for skips, rejects and dry runs).
        """
        dest = attachment_dest(
            self.cfg.out_dir,
            cand.tracker,
            cand.issue_id,
            cand.attachment_id,
            cand.filename,
        )
        if self.cfg.dry_run:
            kind = "sniff" if cand.sniff else "named"
            log(f"  [dry-run] {cand.tracker} {cand.issue_id}: "
                f"{cand.filename or '(no name)'} ({kind}) {cand.issue_url}")
            return 0
        if os.path.exists(dest):
            self.counts["skipped"] += 1
            return 0
        if cand.sniff:
            try:
                if "payload" in cand.extra:
                    data = cand.extra["payload"]
                    if len(data) > self.cfg.sniff_size:
                        data = data[: self.cfg.sniff_size]
                else:
                    data = self._fetch_bytes(cand)
            except FetchError as exc:
                log(f"  fetch failed: {cand.url}: {exc}")
                self.counts["errors"] += 1
                return 0
            kind = self.profile.classify(data)
            if kind is None:
                self.counts["rejected"] += 1
                return 0
            self._write(dest, data)
            self._record(cand, dest, kind, len(data))
            self.counts["downloaded"] += 1
            log(f"  + {os.path.relpath(dest, self.cfg.out_dir)}"
                f" [sniffed: {kind}] {cand.issue_url}")
            return len(data)
        try:
            if cand.extra.get("rest_b64"):
                self._write(dest, self._fetch_bytes(cand))
                status, size = "downloaded", os.path.getsize(dest)
            else:
                status, size = download_to(self.http, cand.url, dest, self.cfg.max_size)
        except FetchError as exc:
            log(f"  download failed: {cand.url}: {exc}")
            self.counts["errors"] += 1
            return 0
        if status != "skipped":
            with open(dest, "rb") as fh:
                head = fh.read(262144)
            if self._is_bot_challenge(head):
                os.remove(dest)
                log(f"  bot-challenge page instead of file: {cand.url}")
                self.counts["errors"] += 1
                return 0
            kind = self.profile.classify(head)
            self._record(cand, dest, kind, size)
            self.counts["downloaded"] += 1
            log(f"  + {os.path.relpath(dest, self.cfg.out_dir)}"
                f" ({size} bytes) {cand.issue_url}")
        return size

    def run_tracker(self, name):
        """Run one tracker to completion, returning per-status counts."""
        tracker = build_tracker(name, self.cfg, self.http, self.state)
        started = time.time()
        self.counts = Counter()
        candidates = tracker.find()
        try:
            while True:
                try:
                    cand = next(candidates)
                except StopIteration:
                    break
                except FetchError as exc:
                    print(f"[{name}] scan error: {exc}")
                    self.counts["errors"] += 1
                    continue
                except Exception as exc:  # one bad bug must not kill the run
                    print(f"[{name}] unexpected scan error: {exc!r}")
                    self.counts["errors"] += 1
                    continue
                try:
                    self.process(cand, print)
                except FetchError as exc:
                    print(f"  fetch failed: {cand.url}: {exc}")
                    self.counts["errors"] += 1
                except Exception as exc:  # one bad bug must not kill the run
                    print(f"  unexpected error on {cand.issue_url}: {exc!r}")
                    self.counts["errors"] += 1
        except KeyboardInterrupt:
            print(f"\n[{name}] interrupted; state saved — rerun to resume.")
            raise
        except FetchError as exc:
            print(f"[{name}] aborted: {exc}")
        elapsed = time.time() - started
        print(
            f"[{name}] done in {elapsed:.0f}s: "
            f"{self.counts['downloaded']} downloaded, "
            f"{self.counts['skipped']} already present, "
            f"{self.counts['rejected']} rejected by content check, "
            f"{self.counts['errors']} errors"
        )
        return self.counts


def run(argv, profile, prog, description):
    """Entry point for a hunt script: parse *argv* and run *profile*.

    *prog* is the script's filename (for help text), *description* its
    module docstring.
    """
    args = parse_args(argv, prog, description)
    names = [n.strip() for n in args.trackers.split(",") if n.strip()]
    unknown = set(names) - set(TRACKER_NAMES)
    if unknown:
        print(f"unknown trackers: {', '.join(sorted(unknown))}", file=sys.stderr)
        print("known trackers: " + ", ".join(TRACKER_NAMES), file=sys.stderr)
        return 2
    if args.patterns:
        patterns = [p.strip() for p in args.patterns.split(",") if p.strip()]
        profile.filename_patterns = patterns
        profile.text_patterns = patterns
    out_dir = args.out
    if out_dir is None:
        repo_root = os.path.dirname(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        )
        out_dir = os.path.join(repo_root, "downloaded")
    config = Config(
        out_dir=out_dir,
        profile=profile,
        max_bugs=args.max_bugs,
        broad=not args.no_broad,
        comments_search=args.comments_search,
        delay=args.delay,
        max_size=args.max_size * 1024 * 1024,
        dry_run=args.dry_run,
        verbose=args.verbose,
        github_token=os.environ.get("GITHUB_TOKEN", ""),
        bugzilla_api_keys={
            name: os.environ.get(f"{name.upper()}_API_KEY", "")
            for name in ("redhat", "suse", "gentoo")
        },
    )
    os.makedirs(config.out_dir, exist_ok=True)
    runner = Runner(config)
    totals = Counter()
    for name in names:
        try:
            totals.update(runner.run_tracker(name))
        except KeyboardInterrupt:
            break
    print(
        f"\nTOTAL: {totals['downloaded']} downloaded, "
        f"{totals['skipped']} already present, "
        f"{totals['rejected']} rejected, {totals['errors']} errors"
    )
    print(f"files: {config.out_dir}  (manifest: {runner.manifest_path})")
    return 0

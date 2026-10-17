#!/usr/bin/env python3
"""Search Linux distro bug trackers for publicly attached shell history files.

Covers Red Hat / Fedora / RHEL (Bugzilla), SUSE / openSUSE (Bugzilla),
Gentoo (Bugzilla), Ubuntu (Launchpad), Debian (debbugs, via web search),
Arch (GitLab), Linux Mint (GitHub) and AlmaLinux (MantisBT).

Files are stored as downloaded/<tracker>/<issue-id>/<attachment-id>/<name>.
Re-running the script resumes where it stopped: finished files are skipped,
partial downloads are continued, and already-scanned issues are remembered
in downloaded/.hunt_state.json.

Examples:
    python3 scripts/hunt_history.py                      # everything
    python3 scripts/hunt_history.py --trackers redhat,ubuntu --max-bugs 10
    python3 scripts/hunt_history.py --trackers mint --dry-run
"""

import argparse
import base64
import json
import os
import sys
import time
from collections import Counter

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from historyhunt.common import (  # noqa: E402
    Config,
    FetchError,
    HttpClient,
    State,
    attachment_dest,
    download_to,
)
from historyhunt.detect import classify_history  # noqa: E402
from historyhunt.trackers import TRACKER_NAMES, build_tracker  # noqa: E402

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def parse_args(argv):
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument(
        "--trackers",
        default=",".join(TRACKER_NAMES),
        help="comma-separated subset of: " + ",".join(TRACKER_NAMES),
    )
    parser.add_argument(
        "--out",
        default=os.path.join(REPO_ROOT, "downloaded"),
        help="output directory (default: <repo>/downloaded)",
    )
    parser.add_argument(
        "--max-bugs",
        type=int,
        default=0,
        help="cap issues scanned per tracker (0 = no cap)",
    )
    parser.add_argument(
        "--no-broad",
        action="store_true",
        help="skip the catch-all 'history' filename search on Bugzilla",
    )
    parser.add_argument(
        "--comments-search",
        action="store_true",
        help="also search Bugzilla comments for history keywords (slow)",
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
        self.http = HttpClient(delay=config.delay, verbose=config.verbose)
        self.state = State(os.path.join(config.out_dir, ".hunt_state.json"))
        self.state.enabled = not config.dry_run
        self.manifest_path = os.path.join(config.out_dir, "manifest.jsonl")
        self.counts = Counter()

    def _record(self, cand, dest, shell, size):
        entry = {
            "path": os.path.relpath(dest, self.cfg.out_dir),
            "tracker": cand.tracker,
            "issue_id": cand.issue_id,
            "attachment_id": cand.attachment_id,
            "filename": os.path.basename(dest),
            "issue_url": cand.issue_url,
            "url": cand.url,
            "shell": shell,
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

    def _keep_sniffed(self, cand, dest, data):
        """Classify sniffed *data*; write to *dest* when it is history."""
        shell = classify_history(data)
        if shell is None:
            self.counts["rejected"] += 1
            return 0
        self._write(dest, data)
        self._record(cand, dest, shell, len(data))
        return len(data)

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
            size = self._keep_sniffed(cand, dest, data)
            if size:
                self.counts["downloaded"] += 1
                shell = classify_history(data)
                log(f"  + {os.path.relpath(dest, self.cfg.out_dir)}"
                    f" [sniffed: {shell}] {cand.issue_url}")
            return size
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
            shell = classify_history(head)
            self._record(cand, dest, shell, size)
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


def main(argv=None):
    args = parse_args(argv)
    names = [n.strip() for n in args.trackers.split(",") if n.strip()]
    unknown = set(names) - set(TRACKER_NAMES)
    if unknown:
        print(f"unknown trackers: {', '.join(sorted(unknown))}", file=sys.stderr)
        print("known trackers: " + ", ".join(TRACKER_NAMES), file=sys.stderr)
        return 2
    config = Config(
        out_dir=args.out,
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


if __name__ == "__main__":
    sys.exit(main())

"""MantisBT adapter (AlmaLinux, bugs.almalinux.org).

Mantis has no anonymous attachment search, but its issue list page accepts a
``search`` parameter that matches summaries, descriptions and notes.  Each
matching issue page links its attachments through ``file_download.php`` with
the original filename.  Attachments with generic names are content-sniffed.
The tracker is small (hundreds of issues), so this is cheap.
"""

import re
import urllib.parse

from ..common import SPECIFIC_PATTERNS, Candidate, FetchError, Progress
from ..detect import is_generic_history_name, is_history_filename

BASE = "https://bugs.almalinux.org"

_ISSUE_LINK_RE = re.compile(r"view\.php\?id=(\d+)")
_ATTACHMENT_RE = re.compile(
    r'href="file_download\.php\?file_id=(\d+)(?:&amp;|&)type=bug"[^>]*>([^<]*)</a>'
)


class MantisTracker:
    """Search AlmaLinux's MantisBT for attached shell history files."""

    def __init__(self, config, http, state, name="almalinux"):
        """Store shared config, HTTP client and crawl state."""
        self.name = name
        self.cfg = config
        self.http = http
        self.state = state

    def _search_issue_ids(self, pattern):
        """Return Mantis issue ids whose text matches *pattern*."""
        url = f"{BASE}/view_all_bug_page.php?search={urllib.parse.quote(pattern)}"
        body = self.http.open(url).body.decode("utf-8", "replace")
        return [int(i) for i in dict.fromkeys(_ISSUE_LINK_RE.findall(body))]

    def _attachments(self, issue_id):
        """Return (file_id, filename) pairs listed on an issue page."""
        body = self.http.open(f"{BASE}/view.php?id={issue_id}").body.decode(
            "utf-8", "replace"
        )
        return _ATTACHMENT_RE.findall(body)

    def find(self):
        """Yield Candidates for history attachments on AlmaLinux's tracker."""
        issues = set()
        for pattern in SPECIFIC_PATTERNS:
            try:
                issues.update(self._search_issue_ids(pattern))
            except FetchError as exc:
                print(f"[{self.name}] search failed for {pattern!r}: {exc}")
        issue_ids = sorted(issues)
        if self.cfg.max_bugs:
            issue_ids = issue_ids[: self.cfg.max_bugs]
        progress = Progress(f"[{self.name}]", len(issue_ids))
        try:
            for issue_id in issue_ids:
                if self.state.is_done(self.name, issue_id):
                    progress.advance()
                    continue
                try:
                    attachments = self._attachments(issue_id)
                except FetchError as exc:
                    progress.log(f"[{self.name}] issue {issue_id}: {exc}")
                    progress.advance()
                    continue
                for file_id, filename in attachments:
                    filename = filename.strip()
                    named_hit = is_history_filename(filename)
                    sniff = is_generic_history_name(filename) or not named_hit
                    if named_hit:
                        sniff = False
                    # Every attachment of a matching issue is considered,
                    # because uploads often carry generic names.
                    yield Candidate(
                        tracker=self.name,
                        issue_id=str(issue_id),
                        attachment_id=file_id,
                        filename=filename or f"file-{file_id}",
                        url=f"{BASE}/file_download.php?file_id={file_id}&type=bug",
                        sniff=sniff,
                        issue_url=f"{BASE}/view.php?id={issue_id}",
                    )
                self.state.mark_done(self.name, issue_id)
                progress.advance()
        finally:
            progress.finish()

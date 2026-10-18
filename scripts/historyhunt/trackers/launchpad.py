"""Launchpad adapter (Ubuntu).

Launchpad has no attachment-filename search, so bugs are found with the
full-text ``searchTasks`` operation on the Ubuntu project and every
attachment of each matching bug is considered: kept when the name matches
the hunt profile, content-sniffed otherwise (attachment titles on
Launchpad are user-chosen and often generic).
"""

import re
import urllib.parse

from ..common import Candidate, FetchError, Progress

API = "https://api.launchpad.net/1.0"


class LaunchpadTracker:
    """Search Ubuntu's Launchpad bugs for profile-matching attachments."""

    def __init__(self, config, http, state, name="ubuntu"):
        """Store shared config, HTTP client and crawl state."""
        self.name = name
        self.cfg = config
        self.http = http
        self.state = state

    def _search_bug_ids(self, pattern):
        """Return Launchpad bug ids whose text matches *pattern*."""
        url = (
            f"{API}/ubuntu?ws.op=searchTasks&ws.size=75&search_text="
            + urllib.parse.quote(pattern)
        )
        ids = []
        while url:
            data = self.http.get_json(url)
            for entry in data.get("entries", []):
                match = re.search(r"/bugs/(\d+)$", entry.get("bug_link", ""))
                if match:
                    ids.append(int(match.group(1)))
            url = data.get("next_collection_link")
            if self.cfg.max_bugs and len(ids) >= self.cfg.max_bugs * 2:
                break
        return ids

    def _attachments(self, bug_id):
        """List attachment entries for *bug_id*."""
        url = f"{API}/bugs/{bug_id}/attachments?ws.size=75"
        entries = []
        while url:
            data = self.http.get_json(url)
            entries.extend(data.get("entries", []))
            url = data.get("next_collection_link")
        return entries

    def find(self):
        """Yield Candidates for profile-matching attachments on Launchpad."""
        bugs = set()
        for pattern in self.cfg.profile.text_patterns:
            try:
                bugs.update(self._search_bug_ids(pattern))
            except FetchError as exc:
                print(f"[{self.name}] search failed for {pattern!r}: {exc}")
        bug_ids = sorted(bugs)
        if self.cfg.max_bugs:
            bug_ids = bug_ids[: self.cfg.max_bugs]
        progress = Progress(f"[{self.name}]", len(bug_ids))
        try:
            for bug_id in bug_ids:
                if self.state.is_done(self.name, bug_id):
                    progress.advance()
                    continue
                try:
                    attachments = self._attachments(bug_id)
                except FetchError as exc:
                    progress.log(f"[{self.name}] bug {bug_id}: {exc}")
                    progress.advance()
                    continue
                for att in attachments:
                    title = att.get("title", "") or ""
                    attachment_id = att.get("self_link", "").rstrip("/").rsplit("/", 1)[-1]
                    cand = Candidate(
                        tracker=self.name,
                        issue_id=str(bug_id),
                        attachment_id=attachment_id,
                        filename=title,
                        url=att.get("data_link", ""),
                        issue_url=f"https://bugs.launchpad.net/bugs/{bug_id}",
                    )
                    if not cand.url:
                        continue
                    if self.cfg.profile.is_target_filename(title):
                        yield cand
                    else:
                        # Launchpad attachment titles are unreliable, so every
                        # attachment of a matching bug gets content-sniffed.
                        cand.sniff = True
                        yield cand
                self.state.mark_done(self.name, bug_id)
                progress.advance()
        finally:
            progress.finish()

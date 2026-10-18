"""Debian BTS adapter.

debbugs has no way to search message bodies or attachments itself, so
candidate bugs are discovered through The Mail Archive, which indexes the
``debian-bugs-dist`` mailing list (a mirror of all bug traffic): searching
it for a profile search term returns messages whose subjects contain
``Bug#<number>``.  For each candidate bug the whole report is downloaded as
an mbox (``bugreport.cgi?mbox=yes&bug=<n>``) and every MIME part is
inspected: parts with matching filenames are kept, plain-text parts are
content-sniffed.  Because debbugs attachments are just MIME parts of bug
mail, parts frequently have no filename at all — the content sniffing is
what finds those.
"""

import mailbox
import os
import re
import tempfile
import time
import urllib.parse

from ..common import Candidate, FetchError, Progress

SEARCH_URL = "https://www.mail-archive.com/search"
BUG_URL = "https://bugs.debian.org/cgi-bin/bugreport.cgi"

_BUG_REF_RE = re.compile(r"Bug#(\d+)")

# Only keep MIME parts of these types; everything else is skipped before
# any content check.
_TEXT_TYPES = {"text/plain", "application/octet-stream", "text/x-sh", ""}


class DebianTracker:
    """Search Debian's BTS for profile-matching attached files."""

    def __init__(self, config, http, state, name="debian"):
        """Store shared config, HTTP client and crawl state."""
        self.name = name
        self.cfg = config
        self.http = http
        self.state = state

    def _search_bug_ids(self, pattern):
        """Return Debian bug numbers found via The Mail Archive for *pattern*."""
        query = urllib.parse.urlencode(
            {"l": "debian-bugs-dist@lists.debian.org", "q": f'"{pattern}"'}
        )
        resp = self.http.open(f"{SEARCH_URL}?{query}")
        text = resp.body.decode("utf-8", "replace")
        time.sleep(1)
        return sorted({int(m) for m in _BUG_REF_RE.findall(text)})

    def _mbox_candidates(self, bug_id):
        """Yield Candidates from every MIME part of a bug's mbox."""
        with tempfile.NamedTemporaryFile(
            suffix=".mbox", prefix=f"deb{bug_id}-", delete=False
        ) as tmp:
            tmp_path = tmp.name
        try:
            resp = self.http.open(
                f"{BUG_URL}?mbox=yes&bug={bug_id}", max_bytes=self.cfg.max_size
            )
            with open(tmp_path, "wb") as fh:
                fh.write(resp.body)
            box = mailbox.mbox(tmp_path)
            for msg_index, message in enumerate(box):
                part_index = 0
                for part in message.walk():
                    if part.get_content_maintype() == "multipart":
                        continue
                    part_index += 1
                    filename = part.get_filename() or ""
                    payload = part.get_payload(decode=True)
                    if payload is None:
                        continue
                    if len(payload) > self.cfg.sniff_size:
                        continue
                    named_hit = bool(filename) and self.cfg.profile.is_target_filename(
                        filename
                    )
                    ctype = part.get_content_type()
                    if not named_hit and ctype not in _TEXT_TYPES:
                        continue
                    yield Candidate(
                        tracker=self.name,
                        issue_id=str(bug_id),
                        attachment_id=f"msg{msg_index}-part{part_index}",
                        filename=filename or f"part-msg{msg_index}-{part_index}.txt",
                        url=f"data:mbox/{bug_id}/{msg_index}/{part_index}",
                        sniff=not named_hit,
                        issue_url=f"https://bugs.debian.org/{bug_id}",
                        extra={"payload": payload},
                    )
        finally:
            os.unlink(tmp_path)

    def find(self):
        """Yield Candidates for profile-matching files on Debian bugs."""
        bug_ids = set()
        for pattern in self.cfg.profile.text_patterns:
            bug_ids.update(self._search_bug_ids(pattern))
            time.sleep(2)
        bug_ids = sorted(bug_ids)
        if self.cfg.max_bugs:
            bug_ids = bug_ids[: self.cfg.max_bugs]
        progress = Progress(f"[{self.name}]", len(bug_ids))
        try:
            for bug_id in bug_ids:
                if self.state.is_done(self.name, bug_id):
                    progress.advance()
                    continue
                try:
                    yield from self._mbox_candidates(bug_id)
                except FetchError as exc:
                    progress.log(f"[{self.name}] bug {bug_id}: {exc}")
                self.state.mark_done(self.name, bug_id)
                progress.advance()
        finally:
            progress.finish()

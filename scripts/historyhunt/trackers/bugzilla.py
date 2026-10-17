"""Bugzilla adapter (Red Hat/Fedora/RHEL, SUSE/openSUSE, Gentoo).

Bugzilla's REST API supports the same "advanced search" as the web UI, so
``f1=attachments.filename&o1=substring&v1=<pattern>`` finds bugs whose
attachments have matching names.  Bugs found that way only need their
history-named or history-ish attachments inspected.  With comment search
enabled, bugs whose discussion mentions history files are also scanned, and
then *all* their small text attachments are content-sniffed — that catches
files uploaded under generic names like ``output.txt``.
"""

import urllib.parse

from ..common import BROAD_PATTERNS, SPECIFIC_PATTERNS, Candidate, Progress
from ..detect import is_generic_history_name, is_history_filename


class BugzillaTracker:
    """Search one Bugzilla instance for shell history attachments."""

    def __init__(self, name, base_url, config, http, state):
        """*name* is the tracker key (e.g. "redhat"), *base_url* the site root
        (the REST API lives at ``<base>/rest.cgi/``)."""
        self.name = name
        self.base = base_url.rstrip("/")
        self.cfg = config
        self.http = http
        self.state = state
        # An API key raises result-size and rate limits (Red Hat caps
        # anonymous searches at 20 results per page).
        self.headers = {}
        key = config.bugzilla_api_keys.get(name, "")
        if key:
            self.headers["Authorization"] = f"Bearer {key}"

    def _search(self, field, pattern):
        """Return all bug ids where *field* substring-matches *pattern*."""
        ids = []
        offset = 0
        while True:
            query = urllib.parse.urlencode(
                {
                    "f1": field,
                    "o1": "substring",
                    "v1": pattern,
                    "include_fields": "id",
                    "limit": 0,
                    "offset": offset,
                }
            )
            data = self.http.get_json(
                f"{self.base}/rest.cgi/bug?{query}", headers=self.headers
            )
            bugs = data.get("bugs", [])
            ids.extend(b["id"] for b in bugs)
            total = data.get("total_matches", len(ids))
            if not bugs or len(ids) >= total:
                return ids
            offset += len(bugs)

    def _attachments(self, bug_id):
        """List attachment metadata dicts for *bug_id* (no file contents)."""
        data = self.http.get_json(
            f"{self.base}/rest.cgi/bug/{bug_id}/attachment?exclude_fields=data",
            headers=self.headers,
        )
        return data.get("bugs", {}).get(str(bug_id), [])

    def find(self):
        """Yield Candidates for history attachments on this Bugzilla."""
        # bug id -> True when every small text attachment should be sniffed
        bugs = {}
        patterns = list(SPECIFIC_PATTERNS)
        if self.cfg.broad:
            patterns += BROAD_PATTERNS
        for pattern in patterns:
            try:
                for bug_id in self._search("attachments.filename", pattern):
                    bugs.setdefault(bug_id, False)
            except Exception as exc:
                print(f"[{self.name}] search failed for {pattern!r}: {exc!r}")
        if self.cfg.comments_search:
            for pattern in SPECIFIC_PATTERNS:
                try:
                    for bug_id in self._search("longdesc", pattern):
                        bugs.setdefault(bug_id, True)
                except Exception as exc:
                    print(f"[{self.name}] comment search failed: {exc!r}")
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
                except Exception as exc:  # one bad bug must not kill the run
                    progress.log(f"[{self.name}] bug {bug_id}: {exc!r}")
                    progress.advance()
                    continue
                sniff_all = bugs[bug_id]
                for att in attachments:
                    if att.get("is_obsolete") or att.get("is_private"):
                        continue
                    filename = att.get("file_name", "")
                    # Download through the REST API, not attachment.cgi: on
                    # some instances (e.g. SUSE) attachment.cgi sits behind
                    # an Anubis bot check while /rest.cgi/ is open.
                    cand = Candidate(
                        tracker=self.name,
                        issue_id=str(bug_id),
                        attachment_id=str(att["id"]),
                        filename=filename,
                        url=f"{self.base}/rest.cgi/bug/attachment/{att['id']}",
                        size=att.get("size", 0),
                        issue_url=f"{self.base}/show_bug.cgi?id={bug_id}",
                        extra={"rest_b64": True, "headers": self.headers},
                    )
                    if is_history_filename(filename):
                        yield cand
                    elif (
                        is_generic_history_name(filename)
                        or (sniff_all and att.get("content_type", "").startswith("text/"))
                    ) and att.get("size", 0) <= self.cfg.sniff_size:
                        cand.sniff = True
                        yield cand
                self.state.mark_done(self.name, bug_id)
                progress.advance()
        finally:
            progress.finish()

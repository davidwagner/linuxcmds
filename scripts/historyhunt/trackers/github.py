"""GitHub adapter (Linux Mint, whose issue tracker is GitHub Issues).

GitHub issue search covers issue bodies and comments.  Files dragged into a
GitHub issue keep their original name in the link
(``https://github.com/user-attachments/files/<id>/<name>``, or the older
``https://github.com/<org>/<repo>/files/<id>/<name>``), so wanted files can
be found by searching for the profile's terms and then extracting upload
links from the issue body and every comment.  Old-style
``cloud.githubusercontent`` asset links carry no filename; those are
content-sniffed.

Unauthenticated rate limits are low (10 search requests/min, 60 API
requests/hour).  Setting the GITHUB_TOKEN environment variable raises them.
"""

import hashlib
import json
import re
import urllib.parse

from ..common import Candidate, FetchError, Progress

ORG = "linuxmint"
API = "https://api.github.com"

# Upload link shapes that preserve the original filename.
_NEW_UPLOAD_RE = re.compile(
    r"https://github\.com/user-attachments/files/([0-9a-fA-F-]+)/([^\s)\]\"'<>]+)"
)
_OLD_UPLOAD_RE = re.compile(
    r"https://github\.com/[\w.-]+/[\w.-]+/files/(\d+)/([^\s)\]\"'<>]+)"
)
# Old asset links have no usable filename; the file must be sniffed.
_ASSET_RE = re.compile(
    r"https://(?:cloud|user-images)\.githubusercontent\.com/[^\s)\]\"'<>]+"
)


class GitHubTracker:
    """Search Linux Mint's GitHub issues for profile-matching files."""

    def __init__(self, config, http, state, name="mint"):
        """Store shared config, HTTP client and crawl state."""
        self.name = name
        self.cfg = config
        self.http = http
        self.state = state
        self.headers = {"Accept": "application/vnd.github+json"}
        if config.github_token:
            self.headers["Authorization"] = f"Bearer {config.github_token}"

    def _search_issues(self, pattern):
        """Return issue dicts in the linuxmint org mentioning *pattern*."""
        query = urllib.parse.quote(f"org:{ORG} {pattern}")
        url = f"{API}/search/issues?q={query}&per_page=100"
        items = []
        while url:
            resp = self.http.open(url, headers=self.headers)
            data = json.loads(resp.body.decode("utf-8", "replace"))
            items.extend(data.get("items", []))
            url = None
            link = resp.headers.get("Link", "")
            match = re.search(r'<([^>]+)>;\s*rel="next"', link)
            if match and len(items) < data.get("total_count", 0):
                url = match.group(1)
        return items

    def _comment_bodies(self, comments_url):
        """Fetch the bodies of all comments on an issue."""
        bodies = []
        url = comments_url + "?per_page=100"
        while url:
            resp = self.http.open(url, headers=self.headers)
            for comment in json.loads(resp.body.decode("utf-8", "replace")):
                bodies.append(comment.get("body") or "")
            url = None
            link = resp.headers.get("Link", "")
            match = re.search(r'<([^>]+)>;\s*rel="next"', link)
            if match:
                url = match.group(1)
        return bodies

    def _links_in(self, text):
        """Yield (attachment_id, filename, url, needs_sniff) from *text*."""
        for match in _NEW_UPLOAD_RE.finditer(text):
            name = urllib.parse.unquote(match.group(2))
            yield match.group(1), name, match.group(0), False
        for match in _OLD_UPLOAD_RE.finditer(text):
            name = urllib.parse.unquote(match.group(2))
            yield match.group(1), name, match.group(0), False
        for match in _ASSET_RE.finditer(text):
            digest = hashlib.md5(match.group(0).encode()).hexdigest()[:12]
            yield digest, "", match.group(0), True

    def find(self):
        """Yield Candidates for profile-matching files on Mint issues."""
        issues = {}
        for pattern in self.cfg.profile.text_patterns:
            try:
                for item in self._search_issues(pattern):
                    issues[item["html_url"]] = item
            except FetchError as exc:
                print(f"[{self.name}] search failed for {pattern!r}: {exc}")
        items = sorted(issues.values(), key=lambda i: i["html_url"])
        if self.cfg.max_bugs:
            items = items[: self.cfg.max_bugs]
        progress = Progress(f"[{self.name}]", len(items))
        try:
            for item in items:
                parts = urllib.parse.urlparse(item["html_url"]).path.split("/")
                # /linuxmint/<repo>/issues/<number>
                issue_id = f"{parts[2]}-{parts[4]}" if len(parts) >= 5 else parts[-1]
                if self.state.is_done(self.name, issue_id):
                    progress.advance()
                    continue
                texts = [item.get("body") or ""]
                try:
                    texts.extend(self._comment_bodies(item["comments_url"]))
                except FetchError as exc:
                    progress.log(f"[{self.name}] {issue_id}: {exc}")
                seen = set()
                for text in texts:
                    for attachment_id, name, url, forced_sniff in self._links_in(text):
                        if url in seen:
                            continue
                        seen.add(url)
                        named_hit = bool(name) and self.cfg.profile.is_target_filename(
                            name
                        )
                        sniff = forced_sniff or self.cfg.profile.is_generic_name(name)
                        if not named_hit and not sniff:
                            continue
                        yield Candidate(
                            tracker=self.name,
                            issue_id=issue_id,
                            attachment_id=attachment_id,
                            filename=name,
                            url=url,
                            sniff=sniff,
                            issue_url=item["html_url"],
                        )
                self.state.mark_done(self.name, issue_id)
                progress.advance()
        finally:
            progress.finish()

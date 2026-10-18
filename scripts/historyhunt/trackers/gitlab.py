"""GitLab adapter (Arch Linux, gitlab.archlinux.org; Alpine, gitlab.alpinelinux.org).

Global search needs an account, but per-group issue search works
anonymously, so issues are found through the distro's group (with
subgroups, which covers the packaging projects).  Files uploaded to an
issue keep their original name in the link (``.../uploads/<hash>/<name>``);
links with profile-matching names are downloaded directly, links with
ambiguous names are content-sniffed.

Known limitation: issue comments are not anonymously readable on Arch's
instance (the notes API returns 401 and the work-item web pages load
comments with JavaScript), so only issue descriptions are scanned.

Arch's site is behind an Anubis anti-bot check that only challenges
browser-like clients; the plain User-Agent used by HttpClient passes.
"""

import json
import re
import urllib.parse

from ..common import Candidate, FetchError, Progress


class GitLabTracker:
    """Search one distro's GitLab group issues for matching attachments."""

    def __init__(self, config, http, state, name, base, group):
        """*name* is the tracker key, *base* the site root, *group* the
        GitLab group whose issues (including subgroups) are searched."""
        self.name = name
        self.base = base.rstrip("/")
        self.group = group
        self.cfg = config
        self.http = http
        self.state = state
        # GitLab upload links: absolute, root-relative (rendered HTML), or
        # project-relative (raw markdown).  The 32-hex hash is the directory.
        host = re.escape(urllib.parse.urlparse(self.base).netloc)
        self._upload_re = re.compile(
            r"(?P<path>(?:https://" + host + r")?/[^\s)\"'<>]*?/uploads/"
            r"(?P<hash>[0-9a-f]{32})/(?P<name>[^\s)\"'<>]+))"
        )

    def _get_pages(self, url):
        """Yield decoded JSON pages of a paginated GitLab list endpoint."""
        sep = "&" if "?" in url else "?"
        page = 1
        while True:
            resp = self.http.open(f"{url}{sep}per_page=100&page={page}")
            yield json.loads(resp.body.decode("utf-8", "replace"))
            next_page = resp.headers.get("x-next-page") or resp.headers.get("X-Next-Page")
            if not next_page:
                return
            page = int(next_page)

    def _search_issues(self, pattern):
        """Return issue dicts in this tracker's group matching *pattern*."""
        query = urllib.parse.quote(pattern)
        url = (
            f"{self.base}/api/v4/groups/{self.group}/issues"
            f"?include_subgroups=true&scope=all&search={query}"
        )
        issues = []
        for page in self._get_pages(url):
            issues.extend(page)
        return issues

    def find(self):
        """Yield Candidates for profile-matching files on this GitLab."""
        profile = self.cfg.profile
        issues = {}
        for pattern in profile.text_patterns:
            try:
                for issue in self._search_issues(pattern):
                    issues[(issue["project_id"], issue["iid"])] = issue
            except FetchError as exc:
                print(f"[{self.name}] search failed for {pattern!r}: {exc}")
        items = sorted(issues.values(), key=lambda i: (i["project_id"], i["iid"]))
        if self.cfg.max_bugs:
            items = items[: self.cfg.max_bugs]
        progress = Progress(f"[{self.name}]", len(items))
        try:
            for issue in items:
                issue_id = f"{issue['project_id']}-{issue['iid']}"
                if self.state.is_done(self.name, issue_id):
                    progress.advance()
                    continue
                # references.full looks like "archlinux/packaging/packages/foo#42";
                # the part before '#' is the project path used for upload URLs
                # written as bare "/uploads/<hash>/<name>" in markdown.
                project_path = issue.get("references", {}).get("full", "")
                project_path = project_path.rsplit("#", 1)[0]
                texts = [issue.get("description") or ""]
                seen = set()
                for text in texts:
                    for match in self._upload_re.finditer(text):
                        path = match.group("path")
                        if path.startswith("http"):
                            url = path
                        elif path.startswith("/uploads/"):
                            url = f"{self.base}/{project_path}{path}"
                        else:
                            url = self.base + path
                        name = urllib.parse.unquote(match.group("name"))
                        if url in seen:
                            continue
                        seen.add(url)
                        attachment_id = match.group("hash")[:16]
                        named_hit = profile.is_target_filename(name)
                        sniff = profile.is_generic_name(name)
                        if not named_hit and not sniff:
                            continue
                        yield Candidate(
                            tracker=self.name,
                            issue_id=issue_id,
                            attachment_id=attachment_id,
                            filename=name,
                            url=url,
                            sniff=sniff,
                            issue_url=issue.get("web_url", ""),
                        )
                self.state.mark_done(self.name, issue_id)
                progress.advance()
        finally:
            progress.finish()

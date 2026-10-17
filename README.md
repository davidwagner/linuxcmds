# linuxcmds

## hunt_history.py — find shell history files people attached to public bug reports

`scripts/hunt_history.py` searches the public bug trackers of the major
Linux distributions for issues where someone attached (or otherwise
uploaded) their shell history — `.bash_history`, `.zsh_history`,
`.histfile`, `fish_history`, `.sh_history`, `.history` and friends — and
downloads those files.

Trackers covered:

| key        | distribution        | tracker software | how issues are found                    |
|------------|---------------------|------------------|-----------------------------------------|
| redhat     | RHEL, Fedora, CentOS| Bugzilla         | attachment filename search (REST API)   |
| suse       | SLES, openSUSE      | Bugzilla         | attachment filename search (REST API)   |
| gentoo     | Gentoo              | Bugzilla         | attachment filename search (REST API)   |
| ubuntu     | Ubuntu              | Launchpad        | full-text bug search, then attachments  |
| debian     | Debian              | debbugs          | Mail Archive search of debian-bugs-dist, then mbox MIME parts |
| arch       | Arch Linux          | GitLab           | group issue search (descriptions only — comments need an account) |
| mint       | Linux Mint          | GitHub Issues    | issue/comment search, upload links      |
| almalinux  | AlmaLinux           | MantisBT         | full-text issue search, attachment links|

Attachments whose names are generic or missing (`output.txt`, unnamed MIME
parts, old `cloud.githubusercontent.com` links) are downloaded and
content-checked: fish's YAML markers, zsh's `: epoch:elapsed;` lines, bash's
`#epoch` timestamps, and a plain-commands heuristic decide whether the file
really is a shell history before it is kept.

Files land in `downloaded/<tracker>/<issue-id>/<attachment-id>/<filename>`.
A `manifest.jsonl` in the output directory records where each file came
from (issue URL, attachment URL, detected shell).  Runs resume where they
stopped: finished files are skipped, partial downloads continue with HTTP
Range requests, and already-scanned issues are remembered in
`downloaded/.hunt_state.json`.

Usage:

    python3 scripts/hunt_history.py                       # search every tracker
    python3 scripts/hunt_history.py --trackers redhat,ubuntu --max-bugs 20
    python3 scripts/hunt_history.py --dry-run             # list finds, download nothing
    python3 scripts/hunt_history.py --comments-search     # also search Bugzilla comments (slow)

No third-party packages are needed.  Optional environment variables raise
rate limits: `GITHUB_TOKEN` (GitHub API), `REDHAT_API_KEY` (and similarly
`SUSE_API_KEY`, `GENTOO_API_KEY` for those Bugzillas).
Tests: `python3 -m pytest tests/test_hunt_e2e.py -v` (live network tests).

# linuxcmds

Two scripts mine the public bug trackers of the major Linux distributions
for files people attached to their bug reports that record executed
commands: `hunt_history.py` collects shell history files, `hunt_logs.py`
collects audit/auth/journald logs (which contain process arguments).

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
| alpine     | Alpine Linux        | GitLab           | group issue search (descriptions only)  |
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

## hunt_logs.py — find audit/auth/journald logs people attached to public bug reports

`scripts/hunt_logs.py` uses the same machinery to find log files that
record *processes executed with their arguments*:

- `audit.log` (and rotations `audit.log.1`, `audit.log.4.gz`, ...) —
  auditd's log; its `EXECVE` records carry the full argv of every audited
  process (`a0="sudo" a1="cat" a2="/etc/shadow"`).
- `auth.log` (Debian/Ubuntu) and `secure` (RHEL/Fedora/SUSE) — record every
  sudo invocation with its command line (`COMMAND=/usr/bin/foo --bar`).
- `syslog*` and `sudo*` logs — same sudo/sshd records.
- journald logs: `journal*` text exports, `Journalctl.txt`,
  `JournalctlErrors.txt`, and binary journal files (`system.journal`,
  `user-1000.journal`, `systemd-journal*`).

Trackers covered are the same nine as above.  Filenames are matched
precisely, so lookalikes such as `sudoers`, `secure-boot.log`,
`audit.rules` or `journald.conf` are ignored.  Attachments with generic or
missing names are content-checked: the audit record format
(`type=EXECVE msg=audit(...)`), traditional and ISO-8601 syslog lines,
journalctl export markers and the binary journald file signature
(`LPKSHHRH`) are recognized; gzipped files are decompressed first.

Files land in `downloaded/<tracker>/<issue-id>/<attachment-id>/<filename>`,
shared with hunt_history.py; the log hunt keeps its own manifest
(`logs_manifest.jsonl`) and state file (`.loghunt_state.json`), so the two
hunts never interfere.  Progress, resume, `--dry-run`, `--max-bugs`,
`--patterns`, `--no-broad` and the rate-limit environment variables work
exactly as for hunt_history.py.

Usage:

    python3 scripts/hunt_logs.py                          # search every tracker
    python3 scripts/hunt_logs.py --trackers redhat --patterns audit.log --max-bugs 20
    python3 scripts/hunt_logs.py --dry-run

Tests: `python3 -m pytest tests/test_hunt_logs_e2e.py -v` (live network
tests).

Notes on trackers not covered: Rocky Linux (bugs.rockylinux.org) and Mageia
sit behind an Anubis anti-bot check that blocks non-browser clients;
bugs.centos.org was unreachable at the time of writing (CentOS Stream bugs
live on Red Hat's Bugzilla, covered by the `redhat` key).  Searching for
`/var/log/messages` (the RHEL-family equivalent of syslog) by filename was
considered and dropped: ~36k matching bugs on Red Hat alone makes a full
scan impractical; syslog-format files still surface through the `syslog`
pattern and through content checking of generically named attachments.

#!/usr/bin/env python3
"""Search Linux distro bug trackers for publicly attached audit/auth/journald logs.

Covers Red Hat / Fedora / RHEL (Bugzilla), SUSE / openSUSE (Bugzilla),
Gentoo (Bugzilla), Ubuntu (Launchpad), Debian (debbugs, via web search),
Arch (GitLab), Alpine (GitLab), Linux Mint (GitHub) and AlmaLinux
(MantisBT).  The companion script hunt_history.py hunts shell history
files with the same machinery.

These logs are wanted because they record processes executed with their
arguments: audit.log EXECVE records carry the full argv, and
auth.log/secure/syslog/journald record every sudo invocation's command
line.

Files are stored as downloaded/<tracker>/<issue-id>/<attachment-id>/<name>.
Re-running the script resumes where it stopped: finished files are skipped,
partial downloads are continued, and already-scanned issues are remembered
in downloaded/.loghunt_state.json.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from historyhunt.detect_logs import logs_profile  # noqa: E402
from historyhunt.runner import run  # noqa: E402

if __name__ == "__main__":
    sys.exit(run(sys.argv[1:], logs_profile(), "hunt_logs.py", __doc__))

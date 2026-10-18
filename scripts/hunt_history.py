#!/usr/bin/env python3
"""Search Linux distro bug trackers for publicly attached shell history files.

Covers Red Hat / Fedora / RHEL (Bugzilla), SUSE / openSUSE (Bugzilla),
Gentoo (Bugzilla), Ubuntu (Launchpad), Debian (debbugs, via web search),
Arch (GitLab), Alpine (GitLab), Linux Mint (GitHub) and AlmaLinux
(MantisBT).  The companion script hunt_logs.py hunts audit/auth/journald
log files with the same machinery.

Files are stored as downloaded/<tracker>/<issue-id>/<attachment-id>/<name>.
Re-running the script resumes where it stopped: finished files are skipped,
partial downloads are continued, and already-scanned issues are remembered
in downloaded/.hunt_state.json.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from historyhunt.detect import history_profile  # noqa: E402
from historyhunt.runner import run  # noqa: E402

if __name__ == "__main__":
    sys.exit(
        run(sys.argv[1:], history_profile(), "hunt_history.py", __doc__)
    )

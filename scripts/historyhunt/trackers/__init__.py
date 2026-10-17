"""Bug tracker adapters.

Each tracker yields :class:`historyhunt.common.Candidate` objects for
attachments that are (by name) or might be (by content) shell history files.
"""

from .bugzilla import BugzillaTracker
from .debian import DebianTracker
from .github import GitHubTracker
from .gitlab import GitLabTracker
from .launchpad import LaunchpadTracker
from .mantis import MantisTracker

BUGZILLA_INSTANCES = {
    # Red Hat's Bugzilla carries RHEL, Fedora and CentOS Stream reports.
    "redhat": "https://bugzilla.redhat.com",
    # SUSE's Bugzilla carries SLES and openSUSE reports.
    "suse": "https://bugzilla.suse.com",
    "gentoo": "https://bugs.gentoo.org",
}

TRACKER_NAMES = list(BUGZILLA_INSTANCES) + [
    "ubuntu",
    "debian",
    "arch",
    "mint",
    "almalinux",
]


def build_tracker(name, config, http, state):
    """Create the tracker adapter called *name* (see TRACKER_NAMES)."""
    if name in BUGZILLA_INSTANCES:
        return BugzillaTracker(name, BUGZILLA_INSTANCES[name], config, http, state)
    factories = {
        "ubuntu": LaunchpadTracker,
        "debian": DebianTracker,
        "arch": GitLabTracker,
        "mint": GitHubTracker,
        "almalinux": MantisTracker,
    }
    if name not in factories:
        raise ValueError(f"unknown tracker: {name}")
    return factories[name](config, http, state)

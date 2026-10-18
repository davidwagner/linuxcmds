"""Bug tracker adapters.

Each tracker yields :class:`historyhunt.common.Candidate` objects for
attachments that are (by name) or might be (by content) the kind of file
the active hunt profile looks for.
"""

from .bugzilla import BugzillaTracker
from .debian import DebianTracker
from .github import GitHubTracker
from .gitlab import GitLabTracker
from .launchpad import LaunchpadTracker
from .mantis import MantisTracker

# Bugzilla instances: tracker key -> site root (REST API at <root>/rest.cgi).
BUGZILLA_INSTANCES = {
    "redhat": "https://bugzilla.redhat.com",
    "suse": "https://bugzilla.suse.com",
    "gentoo": "https://bugs.gentoo.org",
}

# GitLab instances: tracker key -> (site root, group whose issues, including
# subgroups, are searched).
GITLAB_INSTANCES = {
    "arch": ("https://gitlab.archlinux.org", "archlinux"),
    "alpine": ("https://gitlab.alpinelinux.org", "alpine"),
}

TRACKER_NAMES = (
    list(BUGZILLA_INSTANCES)
    + ["ubuntu", "debian"]
    + list(GITLAB_INSTANCES)
    + ["mint", "almalinux"]
)


def build_tracker(name, config, http, state):
    """Create the adapter for tracker *name*."""
    if name in BUGZILLA_INSTANCES:
        return BugzillaTracker(name, BUGZILLA_INSTANCES[name], config, http, state)
    if name in GITLAB_INSTANCES:
        base, group = GITLAB_INSTANCES[name]
        return GitLabTracker(config, http, state, name, base, group)
    factories = {
        "ubuntu": LaunchpadTracker,
        "debian": DebianTracker,
        "mint": GitHubTracker,
        "almalinux": MantisTracker,
    }
    if name not in factories:
        raise ValueError(f"unknown tracker: {name}")
    return factories[name](config, http, state)

"""Recognize shell history files by filename and by content.

Two ways a file can be spotted:

1. By name.  People attach files called ``.bash_history``, ``zsh_history``
   and so on, often with suffixes such as ``.txt`` or ``.bak`` added so the
   tracker accepts them.  :func:`is_history_filename` handles those.

2. By content.  Some attachments have generic names (``output.txt``) or no
   name at all.  :func:`classify_history` looks at the bytes and reports
   which shell's history format the file looks like, or ``None``.

Supported formats: bash, zsh, fish, and the plain ``.history``/``.histfile``
style used by csh/tcsh/ksh.
"""

import gzip
import re

# Suffixes people commonly append when uploading a history file.
_SUFFIX_RE = re.compile(
    r"(?:\.(?:txt|text|log|out|gz|bz2|xz|zip|zst|old|bak|orig|save|sav|swp"
    r"|broken|corrupt|new|copy|backup|\d+)|~)+$"
)

# Shell-specific history basenames, e.g. .bash_history, zsh-history,
# .histfile (zsh), .zhistory (zsh).
_SHELL_HISTORY_RE = re.compile(
    r"^\.?(?:(?:bash|zsh|fish|ksh|csh|tcsh|ash|dash|sh)[._-]?history"
    r"|histfile|zhistory)$"
)

# Bare "history" / ".history": could be a shell history (csh/tcsh/ash) but
# also apt's history.log, a browser history export, etc.  Needs a content
# check before we keep it.
_GENERIC_HISTORY_RE = re.compile(r"^\.?history$")


def _stem(name):
    """Reduce a filename to its core basename for matching.

    Strips directory parts and any number of trailing upload suffixes, so
    ``/tmp/.bash_history.txt.gz`` becomes ``.bash_history``.
    """
    base = name.strip().replace("\\", "/").rsplit("/", 1)[-1].lower()
    prev = None
    while prev != base:
        prev = base
        base = _SUFFIX_RE.sub("", base)
    return base


def is_history_filename(name):
    """Return True if *name* looks like a shell history file on its own.

    Examples that match: ``.bash_history``, ``zsh_history.txt``,
    ``fish_history.bak``, ``.histfile``, ``.zhistory``, ``sh_history.1``.
    """
    return bool(name) and bool(_SHELL_HISTORY_RE.match(_stem(name)))


def is_generic_history_name(name):
    """Return True for names like ``history``/``.history``/``history.txt``.

    These are ambiguous (could be an apt log, browser export, ...), so the
    caller should confirm with :func:`classify_history` before keeping.
    """
    return bool(name) and bool(_GENERIC_HISTORY_RE.match(_stem(name)))


# --- content classification -------------------------------------------------

_FISH_CMD_RE = re.compile(r"^- cmd: ", re.M)
_FISH_WHEN_RE = re.compile(r"^\s+when: \d+$", re.M)
_ZSH_EXTENDED_RE = re.compile(r"^: \d{9,}:\d+;", re.M)
_BASH_TIMESTAMP_RE = re.compile(r"^#\d{9,}$", re.M)
_ASSIGNMENT_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")
_ISO_DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}[T ]")

# First word of lines that commonly appear in interactive shell histories.
_COMMON_COMMANDS = frozenset(
    """
    cd ls ll la dir sudo su doas git grep egrep fgrep cat echo printf vim vi
    nvim nano emacs gedit code apt apt-get apt-cache dpkg dnf yum rpm zypper
    pacman yay paru apk emerge flatpak snap make cmake gcc g++ cc clang ninja
    meson ssh scp rsync sftp ftp tar unzip zip 7z unrar wget curl chmod chown
    chgrp mkdir rmdir rm cp mv ln touch exit clear history man info apropos
    top htop btop ps kill killall pkill jobs bg fg nohup disown pip pip3
    python python2 python3 perl ruby node npm npx yarn docker podman kubectl
    systemctl service journalctl dmesg mount umount fdisk lsblk blkid df du
    find locate which whereis head tail less more sort uniq wc awk sed tr cut
    xargs tee export source pwd date cal whoami id uname hostname
    ping traceroute tracepath netstat ss ip ifconfig iwconfig nmcli nmap gpg
    dig host nslookup whois nc ncat socat telnet lftp aria2c lynx links w3m elinks
    openssl screen tmux dd shred sync reboot shutdown poweroff useradd usermod
    passwd groupadd crontab at diff patch cmp env set unset read sleep watch
    time nice exec eval test true false yes xdg-open gimp firefox chromium
    sqlite3 mysql psql mongo redis-cli grub-mkconfig update-grub mkfs modprobe
    lsmod lspci lsusb dmidecode free vmstat iostat strace ltrace gdb objdump
    readelf nm file strings hexdump od base64 md5sum sha256sum sha1sum gzip
    gunzip bzip2 xz zstd
    """.split()
)


_SCRIPT_KEYWORD_RE = re.compile(
    r"^(if|then|elif|else|fi|for|while|until|do|done|case|esac|function|select"
    r"|\{|\})\b"
)

# Timestamp lines in history files look like comments: "#1697040000" (bash)
# or "#+1127127449" (another extended format).  They are not prose comments.
_TIMESTAMP_COMMENT_RE = re.compile(r"^#\+?\d{9,}$")


def _looks_like_shell_lines(lines):
    """Heuristic: does a plain line list look like interactive shell input?

    Only lines that start with a known command or a ./../~/ invocation
    count.  In particular pure ``VAR=value`` lines do NOT count: environment
    dumps, terminfo entries and config files are almost all assignments,
    which is how they used to slip through.
    """
    good = 0
    comments = 0
    keywords = 0
    for line in lines:
        stripped = line.strip()
        words = stripped.split()
        if not words:
            continue
        if stripped.startswith("#"):
            if not _TIMESTAMP_COMMENT_RE.match(stripped):
                comments += 1
            continue
        if _SCRIPT_KEYWORD_RE.match(stripped):
            keywords += 1
        i = 0
        # Skip leading VAR=value assignments (e.g. "FOO=1 make").
        while i < len(words) and _ASSIGNMENT_RE.match(words[i]):
            i += 1
        if i >= len(words):
            continue  # assignment-only line: not evidence of a history file
        first = words[i]
        base = first.rsplit("/", 1)[-1].lower()
        # Note: bare absolute paths ("/etc/foo {") are NOT counted — config
        # files are full of them.  "./x" and "~/x" are how people actually
        # invoke things from a shell prompt.
        if base in _COMMON_COMMANDS or first.startswith(("./", "../", "~/")):
            good += 1
    if good < 3:
        return False
    # Many comments or shell-script keywords: this is a script or config,
    # not an interactive history.
    if comments / len(lines) > 0.15 or keywords >= 3:
        return False
    return good / len(lines) >= 0.4


def classify_history(data):
    """Classify *data* as shell history content.

    Returns one of ``"bash"``, ``"zsh"``, ``"fish"``, ``"sh"`` (plain
    one-command-per-line history with no recognizable markers), or ``None``
    when the data does not look like a shell history file.  Gzip-compressed
    input is transparently decompressed.
    """
    if data[:2] == b"\x1f\x8b":
        try:
            data = gzip.decompress(data)
        except OSError:
            return None
    text = data[:262144].decode("utf-8", "replace")
    # A shebang means this is a script, not an interactive history.
    if text.startswith("#!"):
        return None
    lines = [ln for ln in text.splitlines() if ln.strip()]
    if len(lines) < 3:
        return None
    # Structured formats first: they are unambiguous.
    if len(_FISH_CMD_RE.findall(text)) >= 3 and _FISH_WHEN_RE.search(text):
        return "fish"
    if len(_ZSH_EXTENDED_RE.findall(text)) >= 2:
        return "zsh"
    if len(_BASH_TIMESTAMP_RE.findall(text)) >= 2:
        return "bash"
    # Reject things that are clearly logs or structured documents before
    # applying the plain-history heuristic.
    noisy = sum(
        1
        for ln in lines
        if ln.startswith(("[", "{", "<")) or _ISO_DATE_RE.match(ln)
    )
    if noisy / len(lines) > 0.5:
        return None
    if _looks_like_shell_lines(lines):
        return "sh"
    return None


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("usage: python -m historyhunt.detect FILE...", file=sys.stderr)
        sys.exit(2)
    status = 0
    for path in sys.argv[1:]:
        with open(path, "rb") as fh:
            shell = classify_history(fh.read())
        name_hit = is_history_filename(path)
        generic_hit = is_generic_history_name(path)
        print(
            f"{path}: content={shell or '-'} "
            f"name={'shell' if name_hit else 'generic' if generic_hit else '-'}"
        )
        if shell is None and not name_hit:
            status = 1
    sys.exit(status)

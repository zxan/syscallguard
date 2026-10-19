# policy.py: parse and validate the SyscallGuard policy file.
# Track: G (Guard runtime & bridge)
# Contract: ARCHITECTURE.md Contract 2 (policy file).
#
# Raises PolicyError on any problem; guard.py prints it to stderr and exits 2.
# Inode lookup (st_ino -> protected_inodes) is guard.py's job (Contract 3); this module only
# checks that each protected path exists.
import ipaddress
import os
import tomllib
from dataclasses import dataclass

MODES = ("audit", "enforce")
KEYS = {"mode", "protect", "allow"}


class PolicyError(Exception):
    """Bad policy file. The message names the bad key or value."""


@dataclass(frozen=True)
class Policy:
    mode: str
    protect: list   # absolute paths in file order; index = protected_inodes value
    allow: list     # ipaddress.IPv4Network / IPv6Network, in file order


def load(path, mode=None):
    """Load and validate the policy at `path`. `mode` is the CLI --mode override."""
    try:
        with open(path, "rb") as f:
            data = tomllib.load(f)
    except OSError as e:
        raise PolicyError(f"{path}: cannot read: {e.strerror}") from None
    except tomllib.TOMLDecodeError as e:
        raise PolicyError(f"{path}: invalid TOML: {e}") from None

    unknown = sorted(set(data) - KEYS)
    if unknown:
        raise PolicyError(f"{path}: unknown key(s): {', '.join(unknown)}")

    file_mode = data.get("mode", "audit")
    for m in (file_mode, mode or file_mode):
        if m not in MODES:
            raise PolicyError(f"{path}: mode must be 'audit' or 'enforce', got {m!r}")

    protect = data.get("protect")
    if not isinstance(protect, list) or not protect:
        raise PolicyError(f"{path}: protect must be a non-empty list of absolute paths")
    for p in protect:
        if not isinstance(p, str) or not os.path.isabs(p):
            raise PolicyError(f"{path}: protect entry must be an absolute path, got {p!r}")
        try:
            os.stat(p)   # follows symlinks: guard.py protects the real file
        except OSError as e:
            raise PolicyError(f"{path}: protect entry {p!r}: {e.strerror}") from None

    allow = data.get("allow", [])   # missing = empty: a tagged process reaches nothing
    if not isinstance(allow, list):
        raise PolicyError(f"{path}: allow must be a list of CIDR strings")
    nets = []
    for a in allow:
        # str check first: ip_network(5) would silently accept an int as 0.0.0.5/32
        if not isinstance(a, str):
            raise PolicyError(f"{path}: allow entry must be a CIDR string, got {a!r}")
        try:
            nets.append(ipaddress.ip_network(a, strict=False))
        except ValueError:
            raise PolicyError(f"{path}: allow entry is not a valid CIDR: {a!r}") from None

    return Policy(mode=mode or file_mode, protect=list(protect), allow=nets)

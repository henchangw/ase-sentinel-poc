"""Canonical hosts and protected-network membership.

Incident parsing accepts any host ``ipaddress`` accepts, then emits IPv4 dotted
decimal or eight lowercase IPv6 groups. Customer ranges still fail closed on
prefix lengths this playbook does not allow, including lengths ``ipaddress``
itself can parse.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass

REASON_DIRTY = "empty, CIDR, or whitespace"
REASON_INVALID_V4 = "invalid IPv4"
REASON_INVALID_V6 = "invalid IPv6"
REASON_MAPPED = "IPv4-mapped IPv6"
REASON_BUILTIN_V4 = (
    "protected built-in range (loopback, RFC1918, link-local, "
    "Azure metadata 169.254.169.254, or CGNAT)"
)
REASON_BUILTIN_V6 = (
    "protected built-in IPv6 range (unspecified, loopback, link-local, or unique local)"
)
REASON_CUSTOMER = "protectedIpRanges"

_V4_PREFIXES = frozenset({8, 16, 24, 32})
_V6_PREFIXES = frozenset({16, 32, 48, 64, 80, 96, 112, 128})

_BUILTIN_V4 = (
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("100.64.0.0/10"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
)
_BUILTIN_V6 = (
    ipaddress.ip_network("::/128"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fe80::/10"),
    ipaddress.ip_network("fc00::/7"),
)


@dataclass(frozen=True)
class Classification:
    original: str
    canonical: str | None
    version: int | None
    reason: str | None


@dataclass(frozen=True)
class ProtectedNetwork:
    source: str
    network: ipaddress.IPv4Network | ipaddress.IPv6Network


def _dirty(value: str, *, allow_slash: bool) -> bool:
    if value == "":
        return True
    if any(character.isspace() for character in value):
        return True
    if "," in value or "%" in value:
        return True
    if not allow_slash and "/" in value:
        return True
    return False


def _mapped(address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    return isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None


def canonical_host(value: str) -> Classification:
    """Classify one incident entity. Does not strip or split the text."""

    if _dirty(value, allow_slash=False):
        return Classification(value, None, None, REASON_DIRTY)
    if ":" in value:
        try:
            parsed = ipaddress.ip_address(value)
        except ValueError:
            return Classification(value, None, None, REASON_INVALID_V6)
        if not isinstance(parsed, ipaddress.IPv6Address):
            return Classification(value, None, None, REASON_INVALID_V6)
        if _mapped(parsed):
            return Classification(value, None, None, REASON_MAPPED)
        # Dotted IPv4 embedded in an IPv6 literal is ambiguous here.
        if "." in value:
            return Classification(value, None, None, REASON_INVALID_V6)
        return Classification(value, parsed.exploded.lower(), 6, None)
    try:
        parsed = ipaddress.ip_address(value)
    except ValueError:
        return Classification(value, None, None, REASON_INVALID_V4)
    if not isinstance(parsed, ipaddress.IPv4Address) or str(parsed) != value:
        return Classification(value, None, None, REASON_INVALID_V4)
    return Classification(value, str(parsed), 4, None)


def parse_protected_ranges(
    entries: object,
) -> tuple[tuple[ProtectedNetwork, ...], tuple[str, ...]]:
    """Return usable networks and the original entries that cannot be used.

    Any invalid entry fails the whole run. Callers must not continue with the
    networks that did parse.
    """

    if isinstance(entries, str) or not isinstance(entries, (list, tuple)):
        return (), ("<protectedIpRanges>",)
    good: list[ProtectedNetwork] = []
    bad: list[str] = []
    for entry in entries:
        if not isinstance(entry, str):
            bad.append(repr(entry))
            continue
        parsed = _parse_one_range(entry)
        if isinstance(parsed, str):
            bad.append(entry)
        else:
            good.append(parsed)
    return tuple(good), tuple(bad)


def _parse_one_range(entry: str) -> ProtectedNetwork | str:
    if _dirty(entry, allow_slash=True) or entry.count("/") > 1:
        return "bad"
    try:
        if "/" not in entry:
            address = ipaddress.ip_address(entry)
            if _mapped(address) or (isinstance(address, ipaddress.IPv6Address) and "." in entry):
                return "bad"
            if isinstance(address, ipaddress.IPv4Address) and str(address) != entry:
                return "bad"
            network = ipaddress.ip_network(f"{address}/{address.max_prefixlen}", strict=False)
        else:
            prefix_token = entry.split("/", 1)[1]
            network = ipaddress.ip_network(entry, strict=False)
            # Reject "/08" and other non-canonical prefix spellings.
            if prefix_token != str(network.prefixlen):
                return "bad"
            if _mapped(network.network_address) or (network.version == 6 and "." in entry):
                return "bad"
    except ValueError:
        return "bad"
    allowed = _V4_PREFIXES if network.version == 4 else _V6_PREFIXES
    if network.prefixlen not in allowed:
        return "bad"
    return ProtectedNetwork(entry, network)


def protection_reason(
    canonical: str,
    version: int,
    ranges: tuple[ProtectedNetwork, ...],
    *,
    override: bool,
) -> str | None:
    """Return a rejection reason, or None when the host may be blocked."""

    if override:
        return None
    address = ipaddress.ip_address(canonical)
    builtins = _BUILTIN_V4 if version == 4 else _BUILTIN_V6
    builtin_reason = REASON_BUILTIN_V4 if version == 4 else REASON_BUILTIN_V6
    for network in builtins:
        if address in network:
            return builtin_reason
    for protected in ranges:
        if protected.network.version == address.version and address in protected.network:
            return REASON_CUSTOMER
    return None

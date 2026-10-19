"""Pure list decisions. No Azure calls and no address parsing."""

from __future__ import annotations

from sentinel_waf_block.models import APPLICATION_GATEWAY


def enforcement_enabled(flag: object) -> bool:
    """Only the JSON boolean true may update a policy."""

    return flag is True


def override_enabled(flag: object) -> bool:
    return flag is True


def split_provider(
    hosts: list[tuple[str, int]],
    provider: str,
) -> tuple[list[str], list[str]]:
    """Return enforceable candidates and unenforced IPv6 addresses.

    Azure Application Gateway does not support IPv6 as an IP block source.
    IPMatch on RemoteAddr is IPv4-only, so those hosts stay out of matchValues
    and do not consume block-list capacity. Front Door can block them.
    """

    if provider != APPLICATION_GATEWAY:
        return [canonical for canonical, _version in hosts], []
    enforceable = [canonical for canonical, version in hosts if version == 4]
    unenforced = [canonical for canonical, version in hosts if version == 6]
    return enforceable, unenforced


def merge_addresses(
    existing: list[str],
    candidates: list[str],
) -> tuple[list[str], list[str]]:
    """Append candidates that are not already present as the same string.

    Existing values are kept verbatim, including duplicate or compressed text.
    """

    present = set(existing)
    new: list[str] = []
    for candidate in candidates:
        if candidate in present:
            continue
        present.add(candidate)
        new.append(candidate)
    return [*existing, *new], new


def exceeds_capacity(merged: list[str], maximum: int) -> bool:
    return len(merged) > maximum

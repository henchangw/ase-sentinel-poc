from sentinel_waf_block.addresses import (
    REASON_BUILTIN_V4,
    REASON_BUILTIN_V6,
    REASON_CUSTOMER,
    REASON_DIRTY,
    REASON_INVALID_V4,
    REASON_INVALID_V6,
    REASON_MAPPED,
    canonical_host,
    parse_protected_ranges,
    protection_reason,
)


EXPANDED = "2001:0db8:0000:0000:0000:0000:0000:0001"


def test_public_ipv4_is_canonical() -> None:
    result = canonical_host("203.0.113.5")
    assert result.canonical == "203.0.113.5"
    assert result.version == 4
    assert result.reason is None


def test_leading_zero_ipv4_is_rejected() -> None:
    result = canonical_host("192.0.2.01")
    assert result.reason == REASON_INVALID_V4
    assert result.canonical is None


def test_dirty_incident_values_are_not_repaired() -> None:
    assert canonical_host("").reason == REASON_DIRTY
    assert canonical_host(" 203.0.113.5").reason == REASON_DIRTY
    assert canonical_host("203.0.113.5/32").reason == REASON_DIRTY
    assert canonical_host("203.0.113.5,198.51.100.8").reason == REASON_DIRTY
    assert canonical_host("fe80::1%eth0").reason == REASON_DIRTY


def test_compressed_and_uppercase_ipv6_are_expanded() -> None:
    assert canonical_host("2001:DB8::1").canonical == EXPANDED
    assert canonical_host("2001:0db8:0000:0000:0000:0000:0000:0001").canonical == EXPANDED


def test_malformed_ipv6_is_rejected() -> None:
    assert canonical_host("not:an:ip").reason == REASON_INVALID_V6
    assert canonical_host("gggg::1").reason == REASON_INVALID_V6


def test_ipv4_mapped_is_rejected_and_not_converted() -> None:
    dotted = canonical_host("::ffff:192.0.2.1")
    expanded = canonical_host("0000:0000:0000:0000:0000:ffff:c000:0201")
    assert dotted.reason == REASON_MAPPED
    assert expanded.reason == REASON_MAPPED
    assert dotted.canonical is None
    assert expanded.canonical is None


def test_dotted_ipv4_embedded_in_ipv6_is_rejected() -> None:
    assert canonical_host("::192.0.2.1").reason == REASON_INVALID_V6
    assert canonical_host("2001:db8::192.0.2.1").reason == REASON_INVALID_V6


def test_builtin_ipv4_categories() -> None:
    ranges, bad = parse_protected_ranges([])
    assert bad == ()
    samples = {
        "0.0.0.1": REASON_BUILTIN_V4,
        "10.1.2.3": REASON_BUILTIN_V4,
        "172.16.5.5": REASON_BUILTIN_V4,
        "192.168.1.20": REASON_BUILTIN_V4,
        "127.0.0.1": REASON_BUILTIN_V4,
        "169.254.1.1": REASON_BUILTIN_V4,
        "169.254.169.254": REASON_BUILTIN_V4,
        "100.64.1.1": REASON_BUILTIN_V4,
        "100.127.255.255": REASON_BUILTIN_V4,
    }
    for address, reason in samples.items():
        assert protection_reason(address, 4, ranges, override=False) == reason
    assert protection_reason("203.0.113.5", 4, ranges, override=False) is None
    assert protection_reason("100.128.0.1", 4, ranges, override=False) is None


def test_builtin_ipv6_categories_and_not_extras() -> None:
    ranges, _bad = parse_protected_ranges([])
    assert protection_reason(canonical_host("::").canonical, 6, ranges, override=False) == REASON_BUILTIN_V6
    assert protection_reason(canonical_host("::1").canonical, 6, ranges, override=False) == REASON_BUILTIN_V6
    assert protection_reason(canonical_host("fe80::1").canonical, 6, ranges, override=False) == REASON_BUILTIN_V6
    assert protection_reason(canonical_host("fd00::1").canonical, 6, ranges, override=False) == REASON_BUILTIN_V6
    assert protection_reason(EXPANDED, 6, ranges, override=False) is None
    assert protection_reason(canonical_host("ff02::1").canonical, 6, ranges, override=False) is None


def test_customer_ranges_use_membership_and_reject_other_prefixes() -> None:
    ranges, bad = parse_protected_ranges(["203.0.113.9/24", "198.51.100.10", "2001:db8::/32"])
    assert bad == ()
    assert protection_reason("203.0.113.8", 4, ranges, override=False) == REASON_CUSTOMER
    assert protection_reason("203.0.113.255", 4, ranges, override=False) == REASON_CUSTOMER
    assert protection_reason("198.51.100.10", 4, ranges, override=False) == REASON_CUSTOMER
    assert protection_reason("198.51.100.11", 4, ranges, override=False) is None
    assert protection_reason(canonical_host("2001:db8::5").canonical, 6, ranges, override=False) == REASON_CUSTOMER
    assert protection_reason(canonical_host("2001:db9::1").canonical, 6, ranges, override=False) is None

    _ranges, rejected = parse_protected_ranges(
        ["172.16.0.0/12", "100.64.0.0/10", "fe80::/10", "fc00::/7", "2001:db8::/40", "192.0.2.0/08", "::ffff:192.0.2.1"]
    )
    assert rejected == (
        "172.16.0.0/12",
        "100.64.0.0/10",
        "fe80::/10",
        "fc00::/7",
        "2001:db8::/40",
        "192.0.2.0/08",
        "::ffff:192.0.2.1",
    )


def test_override_skips_membership_only() -> None:
    ranges, _bad = parse_protected_ranges(["203.0.113.0/24"])
    assert protection_reason("10.1.2.3", 4, ranges, override=True) is None
    assert protection_reason("203.0.113.8", 4, ranges, override=True) is None
    assert canonical_host("::ffff:10.1.2.3").reason == REASON_MAPPED

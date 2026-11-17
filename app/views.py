"""Subnet-based site selection (views) and EDNS Client Subnet helpers.

Pure functions with no I/O and no settings dependency, so the DNS layer
and the tests can drive them directly. A record carries a default IPv4
plus up to a few CIDR -> IPv4 rules; overlapping rules are resolved by
longest-prefix match.

Cache-safety model (RFC 7871 style):

* ``results_in_prefix`` enumerates every distinct answer a prefix can
  produce. If an ECS query reports a prefix whose answers are not
  uniform, the server must answer SERVFAIL instead of an A record that
  a recursor could cache across subnets with different answers.
* ``safe_scope`` returns the largest CIDR around the client whose every
  address selects the same answer, so a successful reply's ECS scope
  never covers a subnet that would have produced a different answer.
"""
from __future__ import annotations

import ipaddress
from typing import List, Optional, Sequence, Set, Tuple, Union

ECS_OPTION_CODE = 8
FAMILY_IPV4 = 1

AnyNetwork = Union[ipaddress.IPv4Network, ipaddress.IPv6Network]
# (network, answer ip) pairs built from a record's "rules" list.
RuleSet = Sequence[Tuple[ipaddress.IPv4Network, str]]

MAX_IPV4_PREFIX = 32


def parse_networks(spec: str) -> Tuple[AnyNetwork, ...]:
    """Parse a comma-separated list of IPs/CIDRs (trusted recursors).

    Raises ValueError on any malformed entry so a bad security-critical
    config fails fast at startup instead of silently trusting no one or
    everyone.
    """
    nets: List[AnyNetwork] = []
    for item in (spec or "").split(","):
        item = item.strip()
        if not item:
            continue
        try:
            nets.append(ipaddress.ip_network(item, strict=False))
        except ValueError as exc:
            raise ValueError(
                f"invalid trusted resolver entry {item!r}: {exc}"
            ) from exc
    return tuple(nets)


def is_trusted(src_ip: str, networks: Sequence[AnyNetwork]) -> bool:
    """True when the UDP source address belongs to a trusted recursor."""
    try:
        addr = ipaddress.ip_address(src_ip)
    except ValueError:
        return False
    return any(
        addr.version == net.version and addr in net for net in networks
    )


def select_answer(
    client: ipaddress.IPv4Address,
    rules: RuleSet,
    default_ip: str,
) -> Tuple[str, Optional[ipaddress.IPv4Network]]:
    """Pick the answer for one client address.

    Returns (ip, matched_rule_network). Overlapping rules are decided by
    longest prefix; no rule matched -> the record's default IPv4.
    """
    best_net: Optional[ipaddress.IPv4Network] = None
    best_ip: Optional[str] = None
    for net, ip in rules:
        if client in net and (best_net is None
                              or net.prefixlen > best_net.prefixlen):
            best_net, best_ip = net, ip
    if best_net is None:
        return default_ip, None
    return best_ip, best_net  # type: ignore[return-value]


def results_in_prefix(
    prefix: ipaddress.IPv4Network,
    rules: RuleSet,
    default_ip: str,
) -> Set[str]:
    """Every distinct answer any address inside ``prefix`` could get.

    Longest-prefix semantics: a rule only contributes its ip where it is
    not shadowed by a longer rule. Any leftover space yields the default.
    """
    remaining = [prefix]
    results: Set[str] = set()
    for net, ip in sorted(rules, key=lambda r: r[0].prefixlen,
                          reverse=True):
        if not net.overlaps(prefix):
            continue
        hit = False
        new_remaining: List[ipaddress.IPv4Network] = []
        for part in remaining:
            if not part.overlaps(net):
                new_remaining.append(part)
            elif net.supernet_of(part) or net == part:
                hit = True  # part fully covered by this rule
            else:
                # CIDRs that overlap always nest, so part ⊃ net here.
                hit = True
                new_remaining.extend(part.address_exclude(net))
        if hit:
            results.add(ip)
        remaining = new_remaining
        if not remaining and len(results) > 1:
            break
    if remaining:
        results.add(default_ip)
    return results


def safe_scope(
    client: ipaddress.IPv4Address,
    rules: RuleSet,
    default_ip: str,
) -> ipaddress.IPv4Network:
    """Largest CIDR containing ``client`` with a single uniform answer.

    The reply's ECS scope is this network's prefix length, so it can
    never cover a subnet whose answer would differ. Bounded by the
    matched rule's network (or 0.0.0.0/0 for the default answer); a /32
    is always uniform, so the loop terminates.
    """
    _, matched = select_answer(client, rules, default_ip)
    current: ipaddress.IPv4Network = (
        matched if matched is not None
        else ipaddress.IPv4Network("0.0.0.0/0")
    )
    while len(results_in_prefix(current, rules, default_ip)) > 1:
        if current.prefixlen >= MAX_IPV4_PREFIX:
            break
        first, second = current.subnets(prefixlen_diff=1)
        current = first if client in first else second
    return current


def parse_ecs_option(data: bytes) -> Optional[ipaddress.IPv4Network]:
    """Decode an ECS option payload into the client source prefix.

    Returns None for non-IPv4 families (ignored, not an error).
    Raises ValueError on malformed payloads.
    """
    if len(data) < 4:
        raise ValueError("ECS option shorter than 4-byte header")
    family = int.from_bytes(data[0:2], "big")
    source = data[2]
    # data[3] is the scope field, which is always 0 in queries.
    if family != FAMILY_IPV4:
        return None
    if source > MAX_IPV4_PREFIX:
        raise ValueError(f"ECS source prefix {source} exceeds /32")
    need = (source + 7) // 8
    addr = data[4:4 + need]
    if len(addr) != need:
        raise ValueError("ECS address bytes truncated")
    packed = addr.ljust(4, b"\x00")
    return ipaddress.IPv4Network((packed, source))


def build_ecs_option(
    source_prefix: ipaddress.IPv4Network,
    scope_len: int,
) -> bytes:
    """Encode a reply ECS option: source echoed, scope = cacheable range."""
    source_len = source_prefix.prefixlen
    need = (source_len + 7) // 8
    return (
        FAMILY_IPV4.to_bytes(2, "big")
        + bytes([source_len, scope_len])
        + source_prefix.network_address.packed[:need]
    )

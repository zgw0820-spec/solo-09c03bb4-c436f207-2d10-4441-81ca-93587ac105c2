"""Unit tests for subnet site selection, ECS codec and zone validation."""
import ipaddress

import pytest

from app import views


def net(s):
    return ipaddress.ip_network(s)


def addr(s):
    return ipaddress.ip_address(s)


# ------------------------------------------------------------ selection
class TestSelectAnswer:
    RULES = [
        (net("10.0.0.0/8"), "10.8.8.8"),
        (net("10.1.0.0/16"), "10.1.1.1"),  # overlaps the /8, longer wins
    ]

    def test_longest_prefix_wins_on_overlap(self):
        ip, matched = views.select_answer(addr("10.1.2.3"), self.RULES,
                                          "192.0.2.1")
        assert ip == "10.1.1.1"
        assert matched == net("10.1.0.0/16")

    def test_shorter_rule_applies_outside_longer_one(self):
        ip, matched = views.select_answer(addr("10.9.9.9"), self.RULES,
                                          "192.0.2.1")
        assert ip == "10.8.8.8"
        assert matched == net("10.0.0.0/8")

    def test_default_when_no_rule_matches(self):
        ip, matched = views.select_answer(addr("172.16.0.1"), self.RULES,
                                          "192.0.2.1")
        assert (ip, matched) == ("192.0.2.1", None)

    def test_no_rules_always_default(self):
        ip, matched = views.select_answer(addr("10.1.2.3"), [], "192.0.2.1")
        assert (ip, matched) == ("192.0.2.1", None)


# ------------------------------------------------- prefix result sets
class TestResultsInPrefix:
    RULES = [
        (net("10.0.0.0/8"), "10.8.8.8"),
        (net("10.1.0.0/16"), "10.1.1.1"),
    ]
    DEFAULT = "192.0.2.1"

    def test_prefix_inside_one_rule_is_uniform(self):
        assert views.results_in_prefix(
            net("10.1.5.0/24"), self.RULES, self.DEFAULT
        ) == {"10.1.1.1"}

    def test_prefix_spanning_rule_and_default_is_mixed(self):
        # 10.0.0.0/8 covers the /16 rule, the rest of the /8 and
        # (via 0/0 thinking) — here the prefix itself is the /8.
        assert views.results_in_prefix(
            net("10.0.0.0/8"), self.RULES, self.DEFAULT
        ) == {"10.8.8.8", "10.1.1.1"}

    def test_prefix_spanning_rule_and_outside_default_is_mixed(self):
        assert views.results_in_prefix(
            net("0.0.0.0/0"), self.RULES, self.DEFAULT
        ) == {"10.8.8.8", "10.1.1.1", "192.0.2.1"}

    def test_prefix_with_no_rules_is_default_only(self):
        assert views.results_in_prefix(
            net("198.51.100.0/24"), self.RULES, self.DEFAULT
        ) == {"192.0.2.1"}

    def test_longer_rule_shadows_shorter_inside_prefix(self):
        # Inside 10.1.0.0/16 the /8 rule never decides: only the /16 ip.
        assert views.results_in_prefix(
            net("10.1.0.0/16"), self.RULES, self.DEFAULT
        ) == {"10.1.1.1"}

    def test_same_ip_rules_collapse_to_one_result(self):
        rules = [(net("10.0.0.0/8"), "1.1.1.1"),
                 (net("10.1.0.0/16"), "1.1.1.1")]
        assert views.results_in_prefix(
            net("10.0.0.0/8"), rules, "2.2.2.2"
        ) == {"1.1.1.1"}

    def test_host_prefix_is_always_uniform(self):
        assert views.results_in_prefix(
            net("10.0.0.0/8"), self.RULES, self.DEFAULT
        ) != set()
        assert len(views.results_in_prefix(
            net("10.1.2.3/32"), self.RULES, self.DEFAULT
        )) == 1


# ------------------------------------------------------------- scope
class TestSafeScope:
    RULES = [
        (net("10.0.0.0/8"), "10.8.8.8"),
        (net("10.1.0.0/16"), "10.1.1.1"),
    ]
    DEFAULT = "192.0.2.1"

    def _check(self, client, expected):
        scope = views.safe_scope(addr(client), self.RULES, self.DEFAULT)
        assert scope == net(expected)
        # invariant: the scope never covers a different answer
        assert len(views.results_in_prefix(scope, self.RULES,
                                           self.DEFAULT)) == 1
        assert addr(client) in scope

    def test_scope_inside_longer_rule_is_that_rule(self):
        self._check("10.1.2.3", "10.1.0.0/16")

    def test_scope_in_shorter_rule_stops_at_longer_rule(self):
        # 10.0.5.6 matches the /8, but the 10.1.0.0/16 rule pokes a hole
        # into it; the widest uniform CIDR around the client is its /16.
        self._check("10.0.5.6", "10.0.0.0/16")

    def test_scope_for_default_client_avoids_all_rules(self):
        self._check("10.2.0.9", "10.2.0.0/15")

    def test_scope_no_rules_is_whole_space(self):
        scope = views.safe_scope(addr("203.0.113.7"), [], self.DEFAULT)
        assert scope == net("0.0.0.0/0")

    def test_scope_when_rule_ip_equals_default(self):
        rules = [(net("10.0.0.0/8"), "9.9.9.9")]
        scope = views.safe_scope(addr("10.3.3.3"), rules, "9.9.9.9")
        # uniform answer everywhere -> widest safe scope
        assert scope == net("0.0.0.0/0") or scope == net("10.0.0.0/8")
        assert len(views.results_in_prefix(scope, rules, "9.9.9.9")) == 1


# ----------------------------------------------------- trusted parsing
class TestTrusted:
    def test_parse_networks(self):
        nets = views.parse_networks(" 10.0.0.2 , 192.168.0.0/16,,")
        assert nets == (net("10.0.0.2/32"), net("192.168.0.0/16"))

    def test_parse_empty(self):
        assert views.parse_networks("") == ()
        assert views.parse_networks("  ") == ()

    def test_parse_invalid_raises(self):
        with pytest.raises(ValueError):
            views.parse_networks("not-a-net")

    def test_is_trusted(self):
        nets = views.parse_networks("10.0.0.0/8,192.0.2.7")
        assert views.is_trusted("10.1.2.3", nets)
        assert views.is_trusted("192.0.2.7", nets)
        assert not views.is_trusted("192.0.2.8", nets)
        assert not views.is_trusted("172.16.0.1", nets)
        assert not views.is_trusted("junk", nets)


# ---------------------------------------------------------- ECS codec
class TestEcsCodec:
    def test_round_trip(self):
        prefix = net("10.1.0.0/16")
        data = views.build_ecs_option(prefix, 16)
        assert data == b"\x00\x01\x10\x10\x0a\x01"
        assert views.parse_ecs_option(data) == prefix

    def test_odd_prefix_length(self):
        prefix = net("10.1.2.0/23")
        data = views.build_ecs_option(prefix, 0)
        assert len(data) == 4 + 3
        assert views.parse_ecs_option(data) == prefix

    def test_host_prefix(self):
        prefix = net("192.0.2.9/32")
        assert views.parse_ecs_option(
            views.build_ecs_option(prefix, 32)) == prefix

    def test_zero_prefix(self):
        prefix = net("0.0.0.0/0")
        data = views.build_ecs_option(prefix, 0)
        assert data == b"\x00\x01\x00\x00"
        assert views.parse_ecs_option(data) == prefix

    def test_non_ipv4_family_ignored(self):
        data = (2).to_bytes(2, "big") + bytes([48, 0]) + b"\x20\x01"
        assert views.parse_ecs_option(data) is None

    def test_malformed_raises(self):
        with pytest.raises(ValueError):
            views.parse_ecs_option(b"\x00\x01\x10")  # too short
        with pytest.raises(ValueError):
            views.parse_ecs_option(b"\x00\x01\x21\x00" + b"\x0a" * 5)
        with pytest.raises(ValueError):
            views.parse_ecs_option(b"\x00\x01\x10\x00\x0a")  # truncated


# --------------------------------------------------- model validation
class TestZoneValidation:
    def payload(self, records):
        from app.models import ZonePayload
        return ZonePayload.model_validate({"records": records})

    def test_plain_a_record_still_accepted(self):
        p = self.payload([{"name": "db.internal.local", "ip": "10.0.0.1"}])
        assert p.records[0].rules == []

    def test_record_with_two_rules_accepted(self):
        p = self.payload([{
            "name": "svc.internal.local",
            "ip": "192.0.2.1",
            "rules": [
                {"cidr": "10.0.0.0/8", "ip": "10.8.8.8"},
                {"cidr": "10.1.0.0/16", "ip": "10.1.1.1"},
            ],
        }])
        assert [r.cidr for r in p.records[0].rules] == [
            "10.0.0.0/8", "10.1.0.0/16"]

    def test_overlapping_rules_allowed(self):
        p = self.payload([{
            "name": "svc.internal.local",
            "ip": "192.0.2.1",
            "rules": [
                {"cidr": "10.0.0.0/8", "ip": "10.8.8.8"},
                {"cidr": "10.1.0.0/16", "ip": "10.1.1.1"},
            ],
        }])
        assert len(p.records[0].rules) == 2

    def test_third_rule_rejected(self):
        with pytest.raises(Exception):
            self.payload([{
                "name": "svc.internal.local",
                "ip": "192.0.2.1",
                "rules": [
                    {"cidr": "10.0.0.0/8", "ip": "10.8.8.8"},
                    {"cidr": "10.1.0.0/16", "ip": "10.1.1.1"},
                    {"cidr": "10.2.0.0/16", "ip": "10.2.2.2"},
                ],
            }])

    def test_duplicate_cidr_rejected(self):
        with pytest.raises(Exception):
            self.payload([{
                "name": "svc.internal.local",
                "ip": "192.0.2.1",
                "rules": [
                    {"cidr": "10.0.0.0/8", "ip": "10.8.8.8"},
                    {"cidr": "10.0.0.0/8", "ip": "10.9.9.9"},
                ],
            }])

    def test_cidr_normalised_to_network_address(self):
        p = self.payload([{
            "name": "svc.internal.local",
            "ip": "192.0.2.1",
            "rules": [{"cidr": "10.1.2.3/16", "ip": "10.1.1.1"}],
        }])
        assert p.records[0].rules[0].cidr == "10.1.0.0/16"

    def test_root_cidr_rejected(self):
        with pytest.raises(Exception):
            self.payload([{
                "name": "svc.internal.local",
                "ip": "192.0.2.1",
                "rules": [{"cidr": "0.0.0.0/0", "ip": "10.1.1.1"}],
            }])

    def test_bad_cidr_rejected(self):
        with pytest.raises(Exception):
            self.payload([{
                "name": "svc.internal.local",
                "ip": "192.0.2.1",
                "rules": [{"cidr": "10.0.0.0/33", "ip": "10.1.1.1"}],
            }])

    def test_ipv6_rule_rejected(self):
        with pytest.raises(Exception):
            self.payload([{
                "name": "svc.internal.local",
                "ip": "192.0.2.1",
                "rules": [{"cidr": "2001:db8::/32", "ip": "10.1.1.1"}],
            }])

    def test_bad_rule_ip_rejected(self):
        with pytest.raises(Exception):
            self.payload([{
                "name": "svc.internal.local",
                "ip": "192.0.2.1",
                "rules": [{"cidr": "10.0.0.0/8", "ip": "not-an-ip"}],
            }])

    def test_zone_record_limit_still_counts_names(self):
        records = [
            {"name": f"h{i}.internal.local", "ip": f"10.0.0.{i}",
             "rules": [{"cidr": "10.1.0.0/16", "ip": "10.1.1.1"}]}
            for i in range(9)
        ]
        with pytest.raises(Exception):
            self.payload(records)

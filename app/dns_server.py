"""Authoritative UDP DNS service for the fixed intranet zone.

Every answer is built from one immutable version snapshot fetched in a
single storage read, so a reply can never mix records of two versions.
While a transfer is in progress the old version stays active and keeps
being answered.

Subnet-based site selection:

* a direct UDP query is located by its source address;
* an EDNS Client Subnet option is honoured only when the UDP source is
  a configured trusted recursor — otherwise it is ignored and the
  source address decides;
* if the reported ECS prefix contains more than one possible answer the
  server replies SERVFAIL rather than hand out an A record a recursor
  could cache across subnets with different answers;
* a successful ECS reply carries a scope that never covers a subnet
  whose answer would differ (see ``views.safe_scope``).
"""
from __future__ import annotations

import ipaddress
import logging
from typing import Dict, List, Optional

from dnslib import A, DNSRecord, EDNSOption, RR, QTYPE, RCODE
from dnslib.server import BaseResolver, DNSServer

from . import views
from .config import settings
from .storage import storage

log = logging.getLogger("dns")

# UDP payload size advertised on our EDNS0 replies.
_EDNS_UDP_LEN = 1232


def _normalise(qname: str) -> str:
    return qname.rstrip(".").lower()


def _record_rules(record: Dict) -> views.RuleSet:
    """Stored records are validated on publish/sync; decode defensively."""
    rules = []
    for raw in record.get("rules") or []:
        try:
            net = ipaddress.ip_network(raw["cidr"], strict=False)
            rules.append((net, raw["ip"]))
        except (KeyError, TypeError, ValueError):  # pragma: no cover
            log.warning("ignoring corrupt rule on %s: %r",
                        record.get("name"), raw)
    return rules


def _extract_ecs(request: DNSRecord) -> Optional[ipaddress.IPv4Network]:
    """Pull the IPv4 ECS source prefix out of the request, if usable."""
    for rr in request.ar:
        if rr.rtype != QTYPE.OPT:
            continue
        options = rr.rdata if isinstance(rr.rdata, list) else []
        for opt in options:
            if opt.code != views.ECS_OPTION_CODE:
                continue
            try:
                return views.parse_ecs_option(bytes(opt.data))
            except ValueError as exc:
                # Malformed ECS: answered as if no ECS was sent.
                log.warning("ignoring malformed ECS option: %s", exc)
                return None
    return None


def _attach_ecs(reply: DNSRecord,
                source_prefix: ipaddress.IPv4Network,
                scope_len: int) -> None:
    data = views.build_ecs_option(source_prefix, scope_len)
    reply.add_ar(
        RR(
            rname="",
            rtype=QTYPE.OPT,
            rclass=_EDNS_UDP_LEN,
            ttl=0,
            rdata=[EDNSOption(views.ECS_OPTION_CODE, data)],
        )
    )


class ZoneResolver(BaseResolver):
    def __init__(self) -> None:
        # Parsed once at startup: a bad trusted-resolver config fails
        # fast here instead of silently mis-trusting clients at runtime.
        self._trusted = views.parse_networks(settings.trusted_ecs_resolvers)
        if self._trusted:
            log.info("honouring ECS from trusted recursors: %s",
                     ", ".join(str(n) for n in self._trusted))

    def _client_view(self, handler, request: DNSRecord):
        """Return (client_ip, ecs_prefix): how this query is located.

        ecs_prefix is set only when a trusted recursor sent a usable ECS
        option; then client_ip is the ECS prefix's address. Otherwise the
        UDP source address decides and ecs_prefix is None.
        """
        src_ip = handler.client_address[0]
        ecs_prefix = _extract_ecs(request)
        if ecs_prefix is not None and views.is_trusted(src_ip,
                                                       self._trusted):
            return ecs_prefix.network_address, ecs_prefix
        if ecs_prefix is not None:
            log.debug("ECS from untrusted source %s ignored", src_ip)
        try:
            addr = ipaddress.ip_address(src_ip)
        except ValueError:  # pragma: no cover - defensive
            return None, None
        if addr.version != 4:
            return None, None
        return addr, None

    def resolve(self, request: DNSRecord, handler) -> DNSRecord:
        reply = request.reply()
        q = request.q
        qname = _normalise(str(q.qname))
        zone = settings.dns_zone.rstrip(".").lower()

        in_zone = qname == zone or qname.endswith("." + zone)
        if not in_zone:
            # This service is authoritative only for the fixed zone.
            reply.header.rcode = RCODE.REFUSED
            return reply

        if QTYPE[q.qtype] != "A":
            # In-zone but not an A query: authoritative NOERROR/NODATA.
            reply.header.rcode = RCODE.NOERROR
            return reply

        # One consistent snapshot -> one version per answer.
        serial, records, _ = storage.get_active_version()
        record: Optional[Dict] = None
        for rec in records:
            if rec["name"] == qname:
                record = rec
                break

        if record is None:
            reply.header.rcode = RCODE.NXDOMAIN
            log.debug("NXDOMAIN %s (serial=%s)", qname, serial)
            return reply

        rules = _record_rules(record)
        default_ip = record["ip"]
        client_ip, ecs_prefix = self._client_view(handler, request)

        if client_ip is None:
            # Non-IPv4 client with no usable ECS: serve the default.
            answer_ip = default_ip
            scope: Optional[ipaddress.IPv4Network] = None
        else:
            answer_ip, _ = views.select_answer(client_ip, rules,
                                               default_ip)
            if ecs_prefix is not None:
                results = views.results_in_prefix(ecs_prefix, rules,
                                                  default_ip)
                if len(results) > 1:
                    # The reported prefix spans subnets with different
                    # answers: refuse rather than emit an A record that
                    # could be cached across those subnets.
                    reply.header.rcode = RCODE.SERVFAIL
                    _attach_ecs(reply, ecs_prefix, 0)
                    log.info(
                        "SERVFAIL %s: ECS %s spans %d different answers "
                        "(serial=%s)",
                        qname, ecs_prefix, len(results), serial,
                    )
                    return reply
                scope = views.safe_scope(client_ip, rules, default_ip)
            else:
                scope = None

        reply.add_answer(RR(q.qname, QTYPE.A, rdata=A(answer_ip), ttl=30))
        if ecs_prefix is not None and scope is not None:
            _attach_ecs(reply, ecs_prefix, scope.prefixlen)
        log.debug("ANSWER %s -> %s (serial=%s, ecs=%s, scope=%s)",
                  qname, answer_ip, serial, ecs_prefix,
                  None if scope is None else scope.prefixlen)
        return reply


class DnsService:
    def __init__(self) -> None:
        self._server: DNSServer | None = None

    def start(self) -> None:
        resolver = ZoneResolver()
        # DNSServer is itself a daemon thread; start_thread() runs the
        # UDP serve loop without blocking the FastAPI startup.
        self._server = DNSServer(
            resolver,
            port=settings.dns_port,
            address=settings.dns_host,
            tcp=False,
        )
        self._server.start_thread()
        log.info(
            "UDP DNS listener on %s:%s (zone=%s, role=%s)",
            settings.dns_host,
            settings.dns_port,
            settings.dns_zone,
            settings.role,
        )

    def stop(self) -> None:
        if self._server is not None:
            try:
                self._server.stop()
            except Exception:  # pragma: no cover
                pass


dns_service = DnsService()

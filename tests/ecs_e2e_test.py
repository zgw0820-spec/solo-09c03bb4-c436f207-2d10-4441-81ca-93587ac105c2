"""End-to-end test for subnet-based site selection and ECS handling.

Run with the project venv:  .venv/bin/python -I tests/ecs_e2e_test.py

Scenarios:
 1. publish a zone where one name has a default IPv4 + two CIDR rules
 2. direct UDP queries are located by their source address (127/8 bind)
 3. trusted recursor: ECS honoured; reply scope never covers a subnet
    with a different answer; overlapping rules -> longest prefix
 4. ECS prefix spanning different answers -> SERVFAIL, never a
    cross-subnet-cacheable A record
 5. ECS from an untrusted source is ignored (source address decides)
 6. backup syncs the view zone and selects identically
 7. invalid rules are rejected and leave the published zone untouched
 8. broken transfer: backup keeps selecting from the old version;
    after reconnect it catches up and late transfers cannot roll back
"""
from __future__ import annotations

import ipaddress
import os
import signal
import socket
import subprocess
import sys
import time
from pathlib import Path

import httpx
from dnslib import DNSRecord, EDNSOption, RR, QTYPE, RCODE

ROOT = Path(__file__).resolve().parent.parent
PY = str(ROOT / ".venv" / "bin" / "python")
DATA = ROOT / "data"
DATA.mkdir(exist_ok=True)

ZONE = "internal.local"
PRIMARY_API = "http://127.0.0.1:18010"
BACKUP_API = "http://127.0.0.1:18011"
PRIMARY_DNS = ("127.0.0.1", 15060)
BACKUP_DNS = ("127.0.0.1", 15061)
BLACKHOLE = "http://127.0.0.1:19999"
TRUSTED = "127.0.0.1"
SYNC_INTERVAL = "2"

PASS, FAIL = 0, 0


def check(name: str, cond: bool, detail: str = "") -> None:
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f"  PASS  {name}")
    else:
        FAIL += 1
        print(f"  FAIL  {name} {detail}")


def wait_http(url: str, timeout: float = 15.0) -> None:
    deadline = time.time() + timeout
    last = None
    while time.time() < deadline:
        try:
            r = httpx.get(url, timeout=1.5)
            if r.status_code == 200:
                return
        except Exception as exc:
            last = exc
        time.sleep(0.3)
    raise RuntimeError(f"service not ready: {url} ({last})")


def ecs_wire(prefix: str, scope: int = 0) -> bytes:
    """Independently built ECS option payload (test-side encoder)."""
    net = ipaddress.ip_network(prefix)
    plen = net.prefixlen
    nbytes = (plen + 7) // 8
    return (
        (1).to_bytes(2, "big")
        + bytes([plen, scope])
        + net.network_address.packed[:nbytes]
    )


def reply_ecs(reply: DNSRecord):
    """Decode the ECS option of a reply -> (source-prefix, scope) or None."""
    for rr in reply.ar:
        if rr.rtype != QTYPE.OPT:
            continue
        options = rr.rdata if isinstance(rr.rdata, list) else []
        for opt in options:
            if opt.code != 8:
                continue
            d = bytes(opt.data)
            src_len, scope = d[2], d[3]
            nbytes = (src_len + 7) // 8
            addr = ipaddress.ip_address(d[4:4 + nbytes].ljust(4, b"\x00"))
            return f"{addr}/{src_len}", scope
    return None


def dns_query(server, name: str, ecs: str | None = None,
              src: str | None = None, timeout: float = 3.0) -> DNSRecord:
    q = DNSRecord.question(name, "A")
    if ecs is not None:
        q.add_ar(RR(rname="", rtype=QTYPE.OPT, rclass=1232, ttl=0,
                    rdata=[EDNSOption(8, ecs_wire(ecs))]))
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    if src:
        sock.bind((src, 0))
    sock.sendto(q.pack(), server)
    data, _ = sock.recvfrom(65535)
    sock.close()
    return DNSRecord.parse(data)


def answers(reply: DNSRecord):
    return [str(rr.rdata) for rr in reply.rr]


def start_service(role: str, api_port: int, dns_port: int, db: str,
                  primary_url: str | None) -> subprocess.Popen:
    env = os.environ.copy()
    env.update(
        {
            "DNS_ROLE": role,
            "DNS_ZONE": ZONE,
            "DB_PATH": db,
            "DNS_HOST": "127.0.0.1",
            "DNS_PORT": str(dns_port),
            "API_HOST": "127.0.0.1",
            "API_PORT": str(api_port),
            "SYNC_INTERVAL": SYNC_INTERVAL,
            "HTTP_TIMEOUT": "3",
            "TRUSTED_ECS_RESOLVERS": TRUSTED,
            "PYTHONUNBUFFERED": "1",
        }
    )
    if primary_url:
        env["PRIMARY_API_URL"] = primary_url
    log = open(DATA / f"{role}-ecs.log", "w")
    return subprocess.Popen(
        [PY, "-I", "-m", "uvicorn", "app.main:app",
         "--host", "127.0.0.1", "--port", str(api_port)],
        cwd=str(ROOT), env=env, stdout=log, stderr=subprocess.STDOUT,
    )


def stop(proc: subprocess.Popen) -> None:
    proc.send_signal(signal.SIGTERM)
    try:
        proc.wait(timeout=10)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()


def publish(api: str, records) -> httpx.Response:
    return httpx.post(f"{api}/api/zone", json={"records": records},
                      timeout=5)


def serial(api: str) -> int:
    return httpx.get(f"{api}/api/version", timeout=3).json()["serial"]


SVC_V1 = {
    "name": f"svc.{ZONE}",
    "ip": "192.0.2.1",
    "rules": [
        {"cidr": "127.0.0.0/24", "ip": "10.0.0.1"},
        {"cidr": "10.1.0.0/16", "ip": "10.1.1.1"},
    ],
}
SVC_V2 = {
    "name": f"svc.{ZONE}",
    "ip": "192.0.2.2",
    "rules": [
        {"cidr": "127.0.0.0/24", "ip": "10.0.0.2"},
        {"cidr": "10.1.0.0/16", "ip": "10.1.1.2"},
    ],
}
PLAIN = {"name": f"plain.{ZONE}", "ip": "10.0.0.21"}


def main() -> int:
    for f in ("primary-ecs.db", "backup-ecs.db"):
        for suffix in ("", "-wal", "-shm"):
            p = DATA / (f + suffix)
            if p.exists():
                p.unlink()

    print("[1] start primary + backup (trusted recursor = 127.0.0.1)")
    primary = start_service("primary", 18010, 15060,
                            str(DATA / "primary-ecs.db"), None)
    backup = start_service("backup", 18011, 15061,
                           str(DATA / "backup-ecs.db"), PRIMARY_API)
    try:
        wait_http(f"{PRIMARY_API}/health")
        wait_http(f"{BACKUP_API}/health")

        print("[2] publish zone: default IPv4 + two CIDR rules + plain A")
        resp = publish(PRIMARY_API, [SVC_V1, PLAIN])
        check("view zone published (201, serial 1)",
              resp.status_code == 201 and resp.json()["serial"] == 1,
              resp.text)
        zone = httpx.get(f"{PRIMARY_API}/api/zone", timeout=3).json()
        svc = [r for r in zone["records"] if r["name"] == f"svc.{ZONE}"]
        check("zone API exposes the rules",
              len(svc) == 1 and svc[0]["rules"] == SVC_V1["rules"],
              str(zone))

        print("[3] direct UDP queries are located by source address")
        r = dns_query(PRIMARY_DNS, f"svc.{ZONE}", src="127.0.0.2")
        check("source inside 127.0.0.0/24 gets rule ip",
              answers(r) == ["10.0.0.1"], str(r))
        r = dns_query(PRIMARY_DNS, f"svc.{ZONE}", src="127.0.1.2")
        check("source outside every rule gets default ip",
              answers(r) == ["192.0.2.1"], str(r))
        r = dns_query(PRIMARY_DNS, f"plain.{ZONE}", src="127.0.0.2")
        check("classic A record without rules still answered",
              answers(r) == ["10.0.0.21"], str(r))
        check("no ECS option echoed on direct answers",
              reply_ecs(r) is None)

        print("[4] trusted recursor: ECS honoured with safe scope")
        r = dns_query(PRIMARY_DNS, f"svc.{ZONE}", ecs="10.1.5.0/24")
        check("ECS 10.1.5.0/24 -> /16 rule ip",
              answers(r) == ["10.1.1.1"], str(r))
        check("reply echoes source, scope = matched /16",
              reply_ecs(r) == ("10.1.5.0/24", 16), str(reply_ecs(r)))
        r = dns_query(PRIMARY_DNS, f"svc.{ZONE}", ecs="10.1.5.9/32")
        check("ECS /32 host -> rule ip, scope widens only to uniform /16",
              answers(r) == ["10.1.1.1"]
              and reply_ecs(r) == ("10.1.5.9/32", 16), str(reply_ecs(r)))
        r = dns_query(PRIMARY_DNS, f"svc.{ZONE}", ecs="10.2.0.0/16")
        check("ECS 10.2.0.0/16 (default region) -> default ip",
              answers(r) == ["192.0.2.1"], str(r))
        check("scope stops at the 10.1.0.0/16 hole (10.2.0.0/15)",
              reply_ecs(r) == ("10.2.0.0/16", 15), str(reply_ecs(r)))
        r = dns_query(PRIMARY_DNS, f"svc.{ZONE}", ecs="192.0.2.0/24")
        check("ECS far from every rule -> default, scope 128/1",
              answers(r) == ["192.0.2.1"]
              and reply_ecs(r) == ("192.0.2.0/24", 1), str(reply_ecs(r)))

        print("[5] ECS prefix spanning different answers -> SERVFAIL")
        for prefix in ("10.0.0.0/8", "0.0.0.0/0", "127.0.0.0/16"):
            r = dns_query(PRIMARY_DNS, f"svc.{ZONE}", ecs=prefix)
            check(f"ECS {prefix} -> SERVFAIL, no A record",
                  r.header.rcode == RCODE.SERVFAIL and len(r.rr) == 0,
                  str(r))
        r = dns_query(PRIMARY_DNS, f"svc.{ZONE}", ecs="10.0.0.0/8")
        check("SERVFAIL carries ECS scope 0 (nothing cacheable)",
              reply_ecs(r) == ("10.0.0.0/8", 0), str(reply_ecs(r)))
        r = dns_query(PRIMARY_DNS, f"svc.{ZONE}")
        check("service unaffected after SERVFAIL",
              r.header.rcode == RCODE.NOERROR)

        print("[6] ECS from an untrusted source is ignored")
        # 127.0.0.2 is NOT in TRUSTED_ECS_RESOLVERS (= 127.0.0.1 only).
        r = dns_query(PRIMARY_DNS, f"svc.{ZONE}", ecs="10.1.5.0/24",
                      src="127.0.0.2")
        check("untrusted ECS ignored: source address decides",
              answers(r) == ["10.0.0.1"], str(r))
        check("no ECS option in reply to untrusted source",
              reply_ecs(r) is None, str(reply_ecs(r)))

        print("[7] backup syncs the view zone and selects identically")
        s = httpx.post(f"{BACKUP_API}/api/sync", timeout=8)
        check("backup synced serial 1",
              s.json()["status"] == "synced"
              and s.json()["local_serial"] == 1, s.text)
        check("backup zone payload equals primary",
              httpx.get(f"{BACKUP_API}/api/zone").json()
              == httpx.get(f"{PRIMARY_API}/api/zone").json())
        r = dns_query(BACKUP_DNS, f"svc.{ZONE}", src="127.0.0.2")
        check("backup direct source selection matches primary",
              answers(r) == ["10.0.0.1"], str(r))
        r = dns_query(BACKUP_DNS, f"svc.{ZONE}", ecs="10.1.5.0/24")
        check("backup ECS selection + scope matches primary",
              answers(r) == ["10.1.1.1"]
              and reply_ecs(r) == ("10.1.5.0/24", 16), str(r))
        r = dns_query(BACKUP_DNS, f"svc.{ZONE}", ecs="10.0.0.0/8")
        check("backup also SERVFAILs on ambiguous ECS prefix",
              r.header.rcode == RCODE.SERVFAIL, str(r))

        print("[8] invalid rules never change the published zone")
        bad_cases = [
            [{**SVC_V2, "rules": SVC_V2["rules"] + [
                {"cidr": "10.2.0.0/16", "ip": "10.2.2.2"}]}],
            [{**SVC_V2, "rules": [{"cidr": "10.0.0.0/33",
                                   "ip": "10.0.0.2"}]}],
            [{**SVC_V2, "rules": [{"cidr": "0.0.0.0/0",
                                   "ip": "10.0.0.2"}]}],
            [{**SVC_V2, "rules": [
                {"cidr": "10.1.0.0/16", "ip": "10.1.1.2"},
                {"cidr": "10.1.0.0/16", "ip": "10.9.9.9"}]}],
        ]
        names = ["three rules", "bad cidr", "root cidr", "duplicate cidr"]
        for name, records in zip(names, bad_cases):
            bad = publish(PRIMARY_API, records)
            check(f"publish with {name} rejected (422)",
                  bad.status_code == 422, bad.text[:200])
        check("serial still 1 after invalid publishes",
              serial(PRIMARY_API) == 1)
        r = dns_query(PRIMARY_DNS, f"svc.{ZONE}", ecs="10.1.5.0/24")
        check("DNS still serves the v1 view after invalid publishes",
              answers(r) == ["10.1.1.1"], str(r))

        print("[9] broken transfer: backup keeps selecting from v1")
        resp = publish(PRIMARY_API, [SVC_V2, PLAIN])
        check("primary advanced to serial 2",
              resp.status_code == 201 and resp.json()["serial"] == 2,
              resp.text)
        stop(backup)
        backup = start_service("backup", 18011, 15061,
                               str(DATA / "backup-ecs.db"), BLACKHOLE)
        wait_http(f"{BACKUP_API}/health")
        time.sleep(float(SYNC_INTERVAL) + 2.0)
        r = dns_query(BACKUP_DNS, f"svc.{ZONE}", ecs="10.1.5.0/24")
        check("backup keeps v1 ECS answer during outage",
              answers(r) == ["10.1.1.1"], str(r))
        r = dns_query(BACKUP_DNS, f"svc.{ZONE}", src="127.0.0.2")
        check("backup keeps v1 source answer during outage",
              answers(r) == ["10.0.0.1"], str(r))
        info = httpx.get(f"{BACKUP_API}/api/version").json()
        check("backup serial stays 1 with failed sync state",
              info["serial"] == 1 and info["last_sync_status"] == "failed",
              str(info))

        print("[10] reconnect: catch up to v2 views, no rollback")
        stop(backup)
        backup = start_service("backup", 18011, 15061,
                               str(DATA / "backup-ecs.db"), PRIMARY_API)
        wait_http(f"{BACKUP_API}/health")
        deadline = time.time() + 15
        while time.time() < deadline and serial(BACKUP_API) < 2:
            time.sleep(0.5)
        check("backup caught up to serial 2", serial(BACKUP_API) == 2)
        r = dns_query(BACKUP_DNS, f"svc.{ZONE}", ecs="10.1.5.0/24")
        check("backup now serves v2 ECS answer",
              answers(r) == ["10.1.1.2"], str(r))
        r = dns_query(BACKUP_DNS, f"svc.{ZONE}", src="127.0.0.2")
        check("backup now serves v2 source answer",
              answers(r) == ["10.0.0.2"], str(r))
        # Late replay of the old complete version must not roll back.
        sqlite_env = os.environ.copy()
        sqlite_env["DB_PATH"] = str(DATA / "backup-ecs.db")
        sqlite_env["PYTHONPATH"] = str(ROOT)
        stale = subprocess.run(
            [PY, "-I", str(ROOT / "tests" / "inject_stale.py")],
            cwd=str(ROOT), env=sqlite_env, capture_output=True, text=True,
        )
        check("late v1 transfer rejected (no rollback)",
              stale.stdout.strip().endswith("False")
              and serial(BACKUP_API) == 2,
              stale.stdout + stale.stderr)
        r = dns_query(BACKUP_DNS, f"svc.{ZONE}", ecs="10.1.5.0/24")
        check("backup still serves v2 after stale transfer",
              answers(r) == ["10.1.1.2"], str(r))

        print("[11] invalid zone from upstream never touches backup's zone")
        # Fake primary serving a structurally valid JSON zone whose rules
        # violate the publish constraints (three CIDR rules on one name).
        import json as _json
        import threading
        from http.server import BaseHTTPRequestHandler, HTTPServer

        bad_zone = {
            "zone": ZONE,
            "serial": 99,
            "records": [{
                "name": f"svc.{ZONE}",
                "ip": "192.0.2.9",
                "rules": [
                    {"cidr": "10.1.0.0/16", "ip": "10.1.1.9"},
                    {"cidr": "10.2.0.0/16", "ip": "10.2.2.9"},
                    {"cidr": "10.3.0.0/16", "ip": "10.3.3.9"},
                ],
            }],
            "published_at": "2026-01-01T00:00:00Z",
        }

        class FakePrimary(BaseHTTPRequestHandler):
            def do_GET(self):
                body = _json.dumps(bad_zone).encode()
                self.send_response(200)
                self.send_header("content-type", "application/json")
                self.send_header("content-length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *args):
                pass

        fake = HTTPServer(("127.0.0.1", 18099), FakePrimary)
        threading.Thread(target=fake.serve_forever, daemon=True).start()
        stop(backup)
        backup = start_service("backup", 18011, 15061,
                               str(DATA / "backup-ecs.db"),
                               "http://127.0.0.1:18099")
        wait_http(f"{BACKUP_API}/health")
        time.sleep(float(SYNC_INTERVAL) + 2.0)
        info = httpx.get(f"{BACKUP_API}/api/version").json()
        check("invalid upstream zone rejected, serial stays 2",
              info["serial"] == 2 and info["last_sync_status"] == "failed",
              str(info))
        r = dns_query(BACKUP_DNS, f"svc.{ZONE}", ecs="10.1.5.0/24")
        check("backup keeps serving v2 view after invalid transfer",
              answers(r) == ["10.1.1.2"], str(r))
        fake.shutdown()
    finally:
        stop(primary)
        if backup.poll() is None:
            stop(backup)

    print(f"\n==== {PASS} passed, {FAIL} failed ====")
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())

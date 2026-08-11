"""Phase 4 (monitoring lens) - Employee Network Activity Monitor.

Reframes the same captured data as a corporate network-activity monitor: the
kind of visibility an employer gets by watching traffic at the office LAN or
VPN concentrator. It answers "what are devices on our network doing?" - which
sites, how much traffic, active when - and, just as importantly, states plainly
what this vantage point CANNOT see.

Honest scope, stated up front and echoed in the output:
  * This measures NETWORK ACTIVITY, not "productivity". Traffic volume is a poor
    proxy for work: reading a document is invisible, an idle autoplaying video
    is loud. Any score here is indicative only.
  * It sees traffic that crosses the monitored network. It does NOT reach a
    remote worker's home network - real deployments capture at the corporate
    VPN/egress, or with an endpoint agent.
  * Modern traffic is encrypted (TLS/QUIC) and increasingly uses privacy
    addressing (IPv6) and encrypted DNS. The "blind spots" section quantifies
    exactly how much of the picture is therefore missing.

Inputs (all already produced by the other phases):
  phase2_capture/outputs/packets.csv          - per-packet, the main source
  phase2_capture/outputs/protocol_stats.json  - totals / protocol mix
  phase1_discovery/outputs/hosts.json          - device inventory (who is who)
  phase3_spoofing/outputs/mac_log.json         - evasion evidence (optional)

Produces:
  phase4_analysis/outputs/activity.json        - the monitoring report

Usage:
    python activity_monitor.py
    python activity_monitor.py --sample     # synthetic data if no capture yet
"""

from __future__ import annotations

import argparse
import ipaddress
import re
import sys
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from shared import config
from shared.utils import (
    banner, die, ensure_dir, human_bytes, info, now_iso, ok, print_table,
    read_csv, read_json, rel, step, warn, write_json,
)

ACTIVITY_JSON = config.PHASE4_OUTPUTS / "activity.json"

# --------------------------------------------------------------------------
# Domain categorisation
#
# Matched as substrings against the full hostname. Order matters only where a
# token could fall in two buckets (handled explicitly, e.g. amazonaws below).
# 'infrastructure' = CDNs / telemetry / reverse-DNS: real traffic, but not a
# "site someone chose to visit", so it is excluded from the work/personal ratio.
# --------------------------------------------------------------------------

CATEGORIES: dict[str, list[str]] = {
    "work-dev": ["github", "gitlab", "bitbucket", "stackoverflow", "python.org",
                 "pypi", "npmjs", "readthedocs", "jetbrains", "docker", "kubernetes",
                 "mvnrepository", "gradle"],
    "work-collab": ["office", "office365", "microsoft", "sharepoint", "outlook",
                    "teams.", "zoom.us", "slack", "atlassian", "jira", "confluence",
                    "notion", "webex", "docs.google", "drive.google", "meet.google",
                    "mail.google", "calendar.google"],
    "cloud-infra": ["amazonaws", "azure", "cloudfront", "cloudflare", "digitalocean",
                    "herokuapp", "vercel", "gcp."],
    "social": ["facebook", "fbcdn", "instagram", "twitter", "x.com", "t.co",
               "reddit", "linkedin", "tiktok", "snapchat", "whatsapp", "telegram",
               "pinterest", "pinimg", "threads.net"],
    "streaming": ["youtube", "ytimg", "googlevideo", "netflix", "nflx", "spotify",
                  "twitch", "hotstar", "primevideo", "disney", "soundcloud", "jiocinema"],
    "shopping": ["amazon.", "flipkart", "myntra", "ajio", "ebay", "aliexpress",
                 "meesho", "snapdeal"],
    "news": ["bbc.", "cnn.", "nytimes", "ndtv", "timesofindia", "thehindu",
             "indianexpress", "reuters", "hindustantimes"],
    "search-ref": ["google.com", "bing.com", "duckduckgo", "wikipedia", "example.com",
                   "quora"],
    "infrastructure": ["gvt2", "googleusercontent", "gstatic", "googleapis", "akamai",
                       "edgekey", "edgesuite", "in-addr.arpa", "beacons", "telemetry",
                       "googlezip", "doubleclick", "google-analytics", "1e100",
                       "cloudflare-dns", "root-servers", "ntp.", "windowsupdate",
                       "msftconnecttest", "msftncsi"],
}

# Which categories count as "work-related" vs "personal" for the ratio.
WORK_CATEGORIES = {"work-dev", "work-collab", "cloud-infra"}
PERSONAL_CATEGORIES = {"social", "streaming", "shopping", "news"}
# search-ref and infrastructure are neutral (excluded from the ratio).

ENCRYPTED_PROTOCOLS = {"TLS", "SSL", "QUIC", "SSH", "HTTPS"}


def _domain_matches(token: str, hay: str) -> bool:
    """Dot-boundary match, so short tokens don't match mid-label.

    `hay` is the domain wrapped in dots ('.host.name.'). A trailing-dot token
    ('amazon.', 'teams.') is a label-prefix intent and matches '.amazon...';
    every other token must line up on dot boundaries, so 't.co' matches 't.co'
    and 'x.t.co' but NOT 'googleusercontent.com'.
    """
    if token.endswith("."):
        return ("." + token) in hay
    return ("." + token + ".") in hay


def categorise(domain: str) -> str:
    d = domain.strip(".").lower()
    hay = "." + d + "."
    # amazonaws is cloud, amazon.<tld> is shopping - disambiguate before the loop
    if "amazonaws" in d:
        return "cloud-infra"
    for category, tokens in CATEGORIES.items():
        if any(_domain_matches(tok, hay) for tok in tokens):
            return category
    return "other"


_MULTI_TLDS = {"co.in", "co.uk", "com.au", "co.jp", "com.br", "co.nz", "ac.in",
               "gov.in", "org.in", "net.in", "co.za"}


def registrable(domain: str) -> str:
    """Reduce a hostname to its registrable domain for cleaner grouping:
    lh3.googleusercontent.com -> googleusercontent.com, but keep known
    two-part TLDs intact (foo.co.in -> foo.co.in)."""
    domain = domain.strip(".").lower()
    if domain.endswith(".in-addr.arpa") or domain.endswith(".arpa"):
        return domain  # reverse-DNS lookups: leave as-is, they are infrastructure
    parts = domain.split(".")
    if len(parts) <= 2:
        return domain
    last_two = ".".join(parts[-2:])
    if last_two in _MULTI_TLDS and len(parts) >= 3:
        return ".".join(parts[-3:])
    return last_two


# --------------------------------------------------------------------------
# Extracting a visited domain from a packet's info column
# --------------------------------------------------------------------------

_DNS_RE = re.compile(r"Standard query(?: response)? (?:0x[0-9a-f]+ )?([A-Za-z0-9._\-]+)")
_SNI_RE = re.compile(r"SNI=([A-Za-z0-9._\-]+)")
_HTTP_RE = re.compile(r"https?://([A-Za-z0-9._\-]+)")


def extract_domain(protocol: str, info: str) -> tuple[str, str] | None:
    """Return (domain, method) where method is dns / tls-sni / http, or None.
    method matters for the blind-spot analysis: dns and http are cleartext
    (would vanish under DNS-over-HTTPS / HTTPS), tls-sni is a leak from within
    the TLS handshake."""
    if not info:
        return None
    if protocol == "DNS":
        m = _DNS_RE.search(info)
        if m:
            return m.group(1), "dns"
    m = _SNI_RE.search(info)
    if m:
        return m.group(1), "tls-sni"
    m = _HTTP_RE.search(info)
    if m:
        return m.group(1), "http"
    return None


# --------------------------------------------------------------------------
# Host / device identity
# --------------------------------------------------------------------------


def _local_network():
    try:
        return ipaddress.ip_network(config.target_network(), strict=False)
    except (ValueError, RuntimeError):
        return None


def is_local_ipv4(ip: str, network) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    if addr.version != 4:
        return False
    return network is None or addr in network


def build_device_index(hosts: list[dict]) -> dict[str, dict]:
    """ip -> {mac, label, is_gateway, open_services}. The gateway is detected as
    any host running a DNS resolver (port 53 / 'domain'), because its captured
    'domains' are everyone's queries relayed through it, not its own browsing."""
    index: dict[str, dict] = {}
    for host in hosts:
        ip = host.get("ip")
        if not ip:
            continue
        services = {p.get("service") for p in host.get("ports", [])
                    if p.get("state") == "open"}
        is_gateway = any(s in ("domain", "dhcps", "dhcp") for s in services) \
            or any(int(p.get("port", 0)) == 53 for p in host.get("ports", [])
                   if p.get("state") == "open")
        index[ip] = {
            "mac": host.get("mac"),
            "label": config.host_label(ip, mac=host.get("mac")),
            "is_gateway": is_gateway,
            "open_services": sorted(s for s in services if s),
        }
    return index


# --------------------------------------------------------------------------
# The analysis
# --------------------------------------------------------------------------


def _parse_ts(value: str):
    try:
        return datetime.fromisoformat(value)
    except (ValueError, TypeError):
        return None


def analyse(packets: list[dict], stats: dict, hosts: list[dict],
            mac_log: dict | None) -> dict:
    network = _local_network()
    devices = build_device_index(hosts)

    # per-employee accumulators
    emp_bytes: Counter = Counter()
    emp_packets: Counter = Counter()
    emp_first: dict[str, datetime] = {}
    emp_last: dict[str, datetime] = {}
    emp_domains: dict[str, Counter] = defaultdict(Counter)
    emp_protocols: dict[str, Counter] = defaultdict(Counter)

    # org-wide / blind-spot accumulators
    org_domains: Counter = Counter()
    domain_category_hits: Counter = Counter()
    domain_methods: Counter = Counter()
    bytes_total = 0
    bytes_encrypted = 0
    bytes_ipv6 = 0
    bytes_local_v4 = 0

    for row in packets:
        src = (row.get("src_ip") or "").strip()
        protocol = (row.get("protocol") or "").upper()
        try:
            length = int(row.get("length") or 0)
        except ValueError:
            length = 0
        bytes_total += length
        if protocol in ENCRYPTED_PROTOCOLS:
            bytes_encrypted += length
        if ":" in src:
            bytes_ipv6 += length
        elif is_local_ipv4(src, network):
            bytes_local_v4 += length

        # domain extraction (attributed to the source = the client asking)
        extracted = extract_domain(protocol, row.get("info") or "")
        domain = method = None
        if extracted:
            raw, method = extracted
            domain = registrable(raw)
            org_domains[domain] += 1
            domain_category_hits[categorise(raw)] += 1
            domain_methods[method] += 1

        # attribute to a known local, non-gateway device = an "employee"
        dev = devices.get(src)
        if dev and not dev["is_gateway"] and is_local_ipv4(src, network):
            emp_bytes[src] += length
            emp_packets[src] += 1
            emp_protocols[src][protocol] += 1
            ts = _parse_ts(row.get("timestamp"))
            if ts:
                emp_first[src] = min(emp_first.get(src, ts), ts)
                emp_last[src] = max(emp_last.get(src, ts), ts)
            if domain and method in ("dns", "tls-sni", "http"):
                emp_domains[src][domain] += 1

    duration = stats.get("duration_seconds") or 1

    employees = []
    for ip in sorted(emp_packets, key=lambda i: -emp_bytes[i]):
        dev = devices.get(ip, {})
        cat_breakdown: Counter = Counter()
        for domain, hits in emp_domains[ip].items():
            cat_breakdown[categorise(domain)] += hits
        active_minutes = None
        if ip in emp_first and ip in emp_last:
            active_minutes = round((emp_last[ip] - emp_first[ip]).total_seconds() / 60, 1)
        employees.append({
            "ip": ip,
            "label": dev.get("label") or f"unidentified device ({ip})",
            "identified": bool(dev.get("label")),
            "mac": dev.get("mac"),
            "bytes": emp_bytes[ip],
            "packets": emp_packets[ip],
            "active_minutes": active_minutes,
            "active_start": emp_first[ip].isoformat() if ip in emp_first else None,
            "active_end": emp_last[ip].isoformat() if ip in emp_last else None,
            "unique_domains": len(emp_domains[ip]),
            "top_domains": [{"domain": d, "hits": h, "category": categorise(d)}
                            for d, h in emp_domains[ip].most_common(10)],
            "category_breakdown": dict(cat_breakdown.most_common()),
            "protocol_mix": dict(emp_protocols[ip].most_common(6)),
            "open_services": dev.get("open_services", []),
            "activity": _activity_indicators(cat_breakdown, active_minutes, duration),
            "flags": _employee_flags(cat_breakdown, dev),
        })

    # org-wide category rollup (uses ALL domain observations, incl. via resolver)
    org_by_category = _rollup_categories(domain_category_hits)

    result = {
        "generated_at": now_iso(),
        "lens": "employee-network-activity",
        "capture": {
            "start": stats.get("capture_start"),
            "end": stats.get("capture_end"),
            "duration_seconds": stats.get("duration_seconds"),
            "total_packets": stats.get("total_packets", len(packets)),
            "total_bytes": bytes_total,
        },
        "employees": employees,
        "organisation": {
            "identified_devices": len(employees),
            "domains_observed": len(org_domains),
            "top_domains": [{"domain": d, "hits": h, "category": categorise(d)}
                            for d, h in org_domains.most_common(20)],
            "category_hits": org_by_category,
        },
        "blind_spots": _blind_spots(bytes_total, bytes_encrypted, bytes_ipv6,
                                    bytes_local_v4, domain_methods, stats, mac_log),
        "privacy_notice": (
            "Lawful workplace monitoring requires a clear purpose, employee "
            "notice/consent, data minimisation, and retention limits. This "
            "report is a technical demonstration on the team's own network; it "
            "is not covert surveillance and must not be used to monitor anyone "
            "without their knowledge and a lawful basis."
        ),
        "scope_caveat": (
            "Measures network activity, not productivity. Sees only traffic "
            "crossing the monitored network (office LAN / VPN egress), not a "
            "remote worker's home network. See blind_spots for what is not "
            "visible."
        ),
    }
    return result


def _activity_indicators(cat_breakdown: Counter, active_minutes, duration_s) -> dict:
    """A transparent, component-based 'engagement' proxy - explicitly NOT a
    productivity measure. Two components, each 0-100, plus a blended headline
    that we label as indicative only."""
    work = sum(cat_breakdown.get(c, 0) for c in WORK_CATEGORIES)
    personal = sum(cat_breakdown.get(c, 0) for c in PERSONAL_CATEGORIES)
    categorised = work + personal
    work_ratio = round(100 * work / categorised) if categorised else None

    duration_min = (duration_s or 0) / 60 or 1
    presence = None
    if active_minutes is not None:
        presence = min(100, round(100 * active_minutes / duration_min))

    parts = [v for v in (work_ratio, presence) if v is not None]
    headline = round(sum(parts) / len(parts)) if parts else None
    return {
        "work_domain_ratio": work_ratio,
        "presence_pct": presence,
        "headline_score": headline,
        "caveat": "Indicative only - proxy for network activity, not productivity.",
    }


def _employee_flags(cat_breakdown: Counter, dev: dict) -> list[str]:
    flags = []
    personal = sum(cat_breakdown.get(c, 0) for c in PERSONAL_CATEGORIES)
    total = sum(cat_breakdown.values())
    if total and personal / total > 0.5:
        flags.append("majority of categorised sites are personal (social/streaming/etc.)")
    if cat_breakdown.get("streaming", 0) > 0:
        flags.append("streaming traffic observed")
    risky = {"mysql", "ms-sql", "telnet", "ftp", "vnc", "rdp", "ms-wbt-server"}
    hit = [s for s in dev.get("open_services", []) if s in risky]
    if hit:
        flags.append(f"exposes risky service(s) on the endpoint: {', '.join(hit)}")
    return flags


def _rollup_categories(hits: Counter) -> dict:
    total = sum(hits.values()) or 1
    return {cat: {"hits": n, "share_pct": round(100 * n / total, 1)}
            for cat, n in hits.most_common()}


def _blind_spots(total, encrypted, ipv6, local_v4, methods, stats, mac_log) -> dict:
    total = total or 1
    protocol_counts = stats.get("protocol_counts", {})
    quic = protocol_counts.get("QUIC", 0)
    dns_cleartext = methods.get("dns", 0) + methods.get("http", 0)
    notes = [
        f"{100 * encrypted / total:.0f}% of traffic BYTES are encrypted "
        f"(TLS/QUIC) - the destination may be inferable but the content is not.",
        f"{100 * ipv6 / total:.0f}% of traffic BYTES came from IPv6 addresses. "
        f"Modern OSes rotate privacy IPv6 addresses, so these cannot be tied to "
        f"a specific device or employee by IP alone - only "
        f"{100 * local_v4 / total:.0f}% was attributable local IPv4.",
        f"{dns_cleartext} site lookups were visible only because DNS/HTTP were "
        f"in cleartext. Enabling DNS-over-HTTPS (which the security report "
        f"recommends) would blind this entirely - the same control that "
        f"protects privacy defeats this monitoring.",
    ]
    spoofed = False
    if mac_log and isinstance(mac_log, dict):
        entries = mac_log.get("entries", [])
        before = next((e for e in entries if e.get("stage") == "before"), None)
        after = next((e for e in reversed(entries) if e.get("stage") == "after"), None)
        if before and after and (before.get("mac") or "").lower() != (after.get("mac") or "").lower():
            spoofed = True
            notes.append(
                "Device identity is forgeable: Phase 3 changed a laptop's MAC in "
                "seconds, so any attribution or block-list keyed on MAC address "
                "can be evaded.")
    return {
        "encrypted_bytes_pct": round(100 * encrypted / total, 1),
        "ipv6_bytes_pct": round(100 * ipv6 / total, 1),
        "attributable_ipv4_bytes_pct": round(100 * local_v4 / total, 1),
        "quic_packets": quic,
        "cleartext_lookups": dns_cleartext,
        "mac_spoof_demonstrated": spoofed,
        "notes": notes,
    }


# --------------------------------------------------------------------------
# Loading / sample
# --------------------------------------------------------------------------


def load_inputs(sample: bool) -> tuple[list[dict], dict, list[dict], dict | None]:
    if sample:
        return _sample_inputs()
    packets_path = config.PACKETS_CSV
    stats_path = config.PROTOCOL_STATS_JSON
    if not packets_path.exists() or not stats_path.exists():
        die(f"need {rel(packets_path)} and {rel(stats_path)} from Phase 2.\n"
            "    Run phase2_capture/analyze.py first, or use --sample.")
    packets = read_csv(packets_path)
    stats = read_json(stats_path)
    hosts = read_json(config.HOSTS_JSON) if config.HOSTS_JSON.exists() else []
    mac_log = read_json(config.MAC_LOG_JSON) if config.MAC_LOG_JSON.exists() else None
    ok(f"loaded {len(packets)} packets, {len(hosts)} hosts")
    return packets, stats, hosts, mac_log


def _sample_inputs():
    warn("running on SAMPLE data - not a real capture")
    base = "2026-08-03T14:00:"
    packets = []
    for i in range(30):
        packets.append({"timestamp": f"{base}{i:02d}", "src_ip": "192.168.1.11",
                        "dst_ip": "8.8.8.8", "protocol": "DNS", "length": "80",
                        "info": f"Standard query {'github.com' if i%3 else 'youtube.com'}"})
    for i in range(20):
        packets.append({"timestamp": f"{base}{30+i%29:02d}", "src_ip": "192.168.1.12",
                        "dst_ip": "1.1.1.1", "protocol": "TLS", "length": "1200",
                        "info": f"TLS Client Hello (SNI={'stackoverflow.com' if i%2 else 'instagram.com'})"})
    stats = {"capture_start": base + "00", "capture_end": base + "59",
             "duration_seconds": 60.0, "total_packets": len(packets),
             "protocol_counts": {"DNS": 30, "TLS": 20}}
    hosts = [
        {"ip": "192.168.1.11", "mac": "AA-AA-AA-AA-AA-11", "ports": []},
        {"ip": "192.168.1.12", "mac": "AA-AA-AA-AA-AA-12",
         "ports": [{"port": 3306, "service": "mysql", "state": "open"}]},
        {"ip": "192.168.1.1", "mac": "AA-AA-AA-AA-AA-01",
         "ports": [{"port": 53, "service": "domain", "state": "open"}]},
    ]
    return packets, stats, hosts, None


# --------------------------------------------------------------------------
# Console summary
# --------------------------------------------------------------------------


def summarise(report: dict) -> None:
    step("Identified devices (employees)")
    rows = []
    for e in report["employees"]:
        act = e["activity"]
        rows.append([
            e["label"][:26], human_bytes(e["bytes"]),
            e["active_minutes"] if e["active_minutes"] is not None else "-",
            e["unique_domains"],
            act["headline_score"] if act["headline_score"] is not None else "-",
            ", ".join(f"{k}:{v}" for k, v in list(e["category_breakdown"].items())[:3]) or "-",
        ])
    print_table(rows, ["DEVICE", "TRAFFIC", "ACTIVE(min)", "#DOM", "SCORE*", "TOP CATEGORIES"])
    print("  * score = indicative activity proxy, NOT productivity")

    step("Top domains across the network")
    print_table([[d["domain"][:34], d["hits"], d["category"]]
                 for d in report["organisation"]["top_domains"][:10]],
                ["DOMAIN", "HITS", "CATEGORY"])

    step("Blind spots (what this monitoring CANNOT see)")
    for note in report["blind_spots"]["notes"]:
        print(f"  - {note}")


def main() -> int:
    parser = argparse.ArgumentParser(description="Phase 4 - employee network activity monitor")
    parser.add_argument("--sample", action="store_true",
                        help="use synthetic data instead of a real capture")
    args = parser.parse_args()

    banner("EMPLOYEE NETWORK ACTIVITY MONITOR")
    info("lens: what an employer sees from network traffic - and what it misses")
    info("scope: activity, not productivity; the team's own network only")

    packets, stats, hosts, mac_log = load_inputs(args.sample)
    step("Analysing traffic")
    report = analyse(packets, stats, hosts, mac_log)
    summarise(report)

    ensure_dir(config.PHASE4_OUTPUTS)
    write_json(ACTIVITY_JSON, report)
    step("Next")
    info(f"{rel(ACTIVITY_JSON)} -> feeds the dashboard's Activity view and the report")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        print()
        warn("interrupted")
        raise SystemExit(130)

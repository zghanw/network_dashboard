"""Live traffic detectors: turn packets into alerts.

Each detector is a plain function that takes the parsed row + raw packet and returns an
alert dict or None. Each keeps its own small, time-windowed state. Thresholds are module
constants up top so they are easy to tune: real networks are noisy, so the right numbers
come from watching your own traffic, not from a textbook.

State here is mutated only from the capture thread (on_packet), so it needs no lock.
"""
import time
from collections import defaultdict, deque
from ipaddress import ip_address

from scapy.all import ARP, DNS, DNSQR, TCP

# ---- tunables: calibrate against your own network ----
SCAN_WINDOW = 10        # seconds to remember a source's destinations
SCAN_TARGETS = 15       # distinct (host, port) targets from one source in the window => scan
DNS_NAME_MAX = 60       # a query name longer than this looks like exfil / DGA / tunneling
WARMUP = 20             # seconds; hosts seen during warm-up are the baseline, not "new"

_start = time.time()


def _is_private(ip):
    try:
        a = ip_address(ip)
        return a.is_private or a.is_loopback or a.is_link_local
    except ValueError:
        return False


def _ip(addr):           # strip ":port" (rsplit is safe: ports are appended only when present)
    return addr.rsplit(":", 1)[0]


def _alert(sev, kind, msg, src=None):
    return {"time": time.strftime("%H:%M:%S"), "ts": time.time(),
            "sev": sev, "kind": kind, "msg": msg, "src": src}


# ---- Port scan: one source touching many distinct host:port targets fast ----
_scan_seen = defaultdict(deque)   # src -> deque of (ts, (dst, dport))
_scan_fired = {}                  # src -> ts of last alert (rate-limit repeats)


def port_scan(row, pkt):
    if TCP not in pkt:
        return None
    src, now = _ip(row["src"]), time.time()
    dq = _scan_seen[src]
    dq.append((now, (_ip(row["dst"]), pkt[TCP].dport)))
    while dq and now - dq[0][0] > SCAN_WINDOW:
        dq.popleft()
    targets = {t for _, t in dq}   # ponytail: O(window) per packet; fine locally, make incremental if hot
    if len(targets) >= SCAN_TARGETS and now - _scan_fired.get(src, 0) > SCAN_WINDOW:
        _scan_fired[src] = now
        return _alert("high", "Port scan", f"{src} probed {len(targets)} targets in {SCAN_WINDOW}s", src)
    return None


# ---- ARP spoofing: an IP's advertised MAC suddenly changes (classic MITM / poisoning) ----
_arp_map = {}   # ip -> mac last seen claiming it


def arp_spoof(row, pkt):
    if ARP not in pkt or pkt[ARP].op != 2:   # op 2 = "is-at" reply carries the binding
        return None
    ip, mac = pkt[ARP].psrc, pkt[ARP].hwsrc
    prev = _arp_map.get(ip)
    _arp_map[ip] = mac
    if prev and prev != mac:
        return _alert("high", "ARP spoof", f"{ip} moved {prev} -> {mac} (possible MITM)", ip)
    return None


# ---- DNS anomaly: absurdly long query names (exfil / domain-generation / tunneling) ----
_dns_fired = {}   # name -> ts (rate-limit repeats of the same name)


def dns_anomaly(row, pkt):
    if DNS not in pkt or not pkt[DNS].qd:
        return None
    try:
        name = pkt[DNSQR].qname.decode("utf-8", "replace").rstrip(".").lower()
    except Exception:
        return None
    if name.endswith((".ip6.arpa", ".in-addr.arpa")):
        return None  # reverse-DNS PTR lookups are long by design (incl. our own enrichment), not anomalies
    if len(name) >= DNS_NAME_MAX and time.time() - _dns_fired.get(name, 0) > 30:
        _dns_fired[name] = time.time()
        return _alert("med", "DNS anomaly", f"long name ({len(name)} chars): {name[:48]}...", _ip(row["src"]))
    return None


# ---- New device: first sighting of a local host after the baseline warm-up ----
_seen_hosts = set()


def new_device(row, pkt):
    src = _ip(row["src"])
    if not _is_private(src) or src in _seen_hosts:
        return None
    _seen_hosts.add(src)
    if time.time() - _start < WARMUP:   # everything during warm-up is baseline, not an alert
        return None
    return _alert("low", "New device", f"first sighting of {src} on your network", src)


DETECTORS = [port_scan, arp_spoof, dns_anomaly, new_device]


def detect(row, pkt):
    """Run every detector; a bug in one must never kill the capture, so each is guarded."""
    out = []
    for det in DETECTORS:
        try:
            a = det(row, pkt)
            if a:
                out.append(a)
        except Exception:
            pass
    return out

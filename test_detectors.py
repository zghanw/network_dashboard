"""Self-check for the detectors. Runs without Npcap: python test_detectors.py"""
from scapy.all import ARP, DNS, DNSQR, IP, TCP, UDP, Ether

import detectors
from detectors import SCAN_TARGETS, arp_spoof, dns_anomaly, new_device, port_scan

def row(src, dst):
    return {"src": f"{src}:11111", "dst": f"{dst}:0"}


# Port scan: one source hitting SCAN_TARGETS distinct ports within the window fires once.
fired = None
for i in range(SCAN_TARGETS):
    pkt = Ether() / IP(src="10.0.0.5", dst="10.0.0.9") / TCP(dport=1000 + i)
    a = port_scan(row("10.0.0.5", "10.0.0.9"), pkt)
    if a:
        fired = a
assert fired and fired["kind"] == "Port scan" and fired["sev"] == "high", fired

# Regression: a server replying across many established connections uses the client's
# distinct ephemeral port as dport on every reply, which used to look identical to the
# server "probing" that many targets. Found live: 160.79.104.10 (a normal HTTPS server)
# was flagged as a port scanner on every busy page load. ACK/SYN-ACK replies must not count.
for i in range(SCAN_TARGETS):
    ack_reply = Ether() / IP(src="10.0.0.6", dst="10.0.0.7") / TCP(sport=443, dport=2000 + i, flags="A")
    assert port_scan(row("10.0.0.6", "10.0.0.7"), ack_reply) is None, "ACK replies must not alert"
    syn_ack = Ether() / IP(src="10.0.0.6", dst="10.0.0.7") / TCP(sport=443, dport=3000 + i, flags="SA")
    assert port_scan(row("10.0.0.6", "10.0.0.7"), syn_ack) is None, "SYN-ACK replies must not alert"

# ARP spoof: first binding is baseline; a second MAC for the same IP alerts.
r = row("0.0.0.0", "0.0.0.0")
assert arp_spoof(r, Ether() / ARP(op=2, psrc="10.0.0.1", hwsrc="aa:aa:aa:aa:aa:aa")) is None
spoof = arp_spoof(r, Ether() / ARP(op=2, psrc="10.0.0.1", hwsrc="bb:bb:bb:bb:bb:bb"))
assert spoof and spoof["kind"] == "ARP spoof", spoof

# DNS anomaly: an over-long query name is flagged.
long_name = "a" * 70 + ".exfil.example"
dns_pkt = Ether() / IP() / UDP() / DNS(qd=DNSQR(qname=long_name))
dns = dns_anomaly(row("10.0.0.5", "8.8.8.8"), dns_pkt)
assert dns and dns["kind"] == "DNS anomaly", dns
# A normal short name is not flagged.
ok = dns_anomaly(row("10.0.0.5", "8.8.8.8"), Ether() / IP() / UDP() / DNS(qd=DNSQR(qname="example.com")))
assert ok is None, ok
# Reverse-DNS PTR queries are long by design and must not be flagged.
rev = ".".join("f" * 32) + ".ip6.arpa"   # ~72-char IPv6 reverse-lookup name
rev_pkt = Ether() / IP() / UDP() / DNS(qd=DNSQR(qname=rev))
assert dns_anomaly(row("10.0.0.5", "8.8.8.8"), rev_pkt) is None, "reverse DNS must not alert"

# New device: IPv4 first sighting alerts once, past warm-up.
detectors._start = 0   # fast-forward past WARMUP
seen = new_device(row("192.168.1.50", "0.0.0.0"), Ether())
assert seen and seen["kind"] == "New device" and seen["sev"] == "low", seen
assert new_device(row("192.168.1.50", "0.0.0.0"), Ether()) is None, "repeat sighting must not re-alert"
# Regression: IPv6 addresses rotate (SLAAC privacy extensions, link-local churn), so the
# same physical host kept re-alerting as "new" every time its address changed — 45+ alerts
# in a few minutes on a real network. IPv4 stays the device identity; IPv6 never alerts.
assert new_device(row("fe80::1234:5678:9abc:def0", "ff02::1"), Ether()) is None, "IPv6 must not alert"
assert new_device(row("fc01::abcd:1", "ff02::1"), Ether()) is None, "IPv6 (ULA) must not alert"

print("all detector checks passed")

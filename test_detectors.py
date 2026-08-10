"""Self-check for the detectors. Runs without Npcap: python test_detectors.py"""
from scapy.all import ARP, DNS, DNSQR, IP, TCP, UDP, Ether

from detectors import SCAN_TARGETS, arp_spoof, dns_anomaly, port_scan


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

print("all detector checks passed")

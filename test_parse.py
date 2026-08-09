"""Self-check for the parse/classify path. Runs without Npcap: python test_parse.py"""
from scapy.all import ARP, DNS, DNSQR, IP, TCP, UDP, Ether

from main import RECENT, STATE, on_packet, origin_allowed, parse

https = parse(Ether() / IP(src="192.168.1.10", dst="1.1.1.1") / TCP(sport=51000, dport=443))
assert https["proto"] == "HTTPS", https
assert https["src"] == "192.168.1.10:51000" and https["dst"] == "1.1.1.1:443", https

dns = parse(Ether() / IP(src="192.168.1.10", dst="8.8.8.8") / UDP(sport=5000, dport=53)
            / DNS(qd=DNSQR(qname="example.com")))
assert dns["proto"] == "DNS", dns

arp = parse(Ether() / ARP(pdst="192.168.1.1"))
assert arp["proto"] == "ARP", arp

on_packet(Ether() / IP(src="192.168.1.10", dst="1.1.1.1") / TCP(dport=443))
assert STATE["total_packets"] == 1 and STATE["protocols"]["HTTPS"] == 1
assert STATE["talkers"]["192.168.1.10"] == STATE["total_bytes"] > 0
assert STATE["edges"][("192.168.1.10", "1.1.1.1")] == STATE["total_bytes"] > 0  # graph edge tracked
assert len(RECENT) == 1 and RECENT[0]["id"] == 0

# CSWSH origin guard: same-host and non-browser clients allowed, cross-site rejected.
assert origin_allowed(None)                          # non-browser client (curl/python)
assert origin_allowed("http://localhost:8000")       # same-origin page load
assert origin_allowed("http://127.0.0.1:8000")
assert not origin_allowed("https://evil.com")         # cross-site attacker page
assert not origin_allowed("http://localhost.evil.com")  # suffix trick must not pass

print("all checks passed")

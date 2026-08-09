"""Local network monitor: Scapy capture -> FastAPI WebSocket -> live dashboard.

Run as Administrator (Npcap required on Windows): python main.py [--iface NAME] [--filter BPF]
"""
import argparse
import asyncio
import json
import socket
import threading
import time
from collections import Counter, deque
from concurrent.futures import ThreadPoolExecutor
from ipaddress import ip_address
from urllib.parse import urlparse

import uvicorn
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse
from scapy.all import ARP, DNS, ICMP, IP, IPv6, TCP, UDP, AsyncSniffer, Ether

app = FastAPI()

LOCK = threading.Lock()
RECENT = deque(maxlen=500)  # rows for the live packet table
STATE = {
    "next_id": 0,
    "total_packets": 0,
    "total_bytes": 0,
    "protocols": Counter(),
    "talkers": Counter(),  # bytes per source IP
    "edges": Counter(),  # bytes per (src ip, dst ip) pair, for the connection graph
    "macs": {},  # local ip -> sender MAC, for vendor lookup
    "error": None,  # sniffer startup failure, shown in the UI
}

PORT_NAMES = {80: "HTTP", 8080: "HTTP", 443: "HTTPS", 22: "SSH", 25: "SMTP",
              123: "NTP", 1900: "SSDP", 5353: "mDNS", 3389: "RDP"}

# Enrichment: turn raw IPs into names. LAN hosts -> hardware vendor via the MAC OUI
# (first 3 bytes); external hosts -> reverse-DNS hostname. Both cached; DNS runs in a
# worker pool so a slow lookup never stalls the capture or the socket loop.
# ponytail: curated OUI subset covers common home gear; drop in the full IEEE list for full coverage.
OUI_VENDORS = {
    "ac:de:48": "Apple", "a4:83:e7": "Apple", "dc:a9:04": "Apple", "f0:18:98": "Apple", "88:66:5a": "Apple",
    "00:1a:8a": "Samsung", "5c:0a:5b": "Samsung", "8c:77:12": "Samsung", "34:23:87": "Samsung",
    "3c:5a:b4": "Google", "f4:f5:e8": "Google", "54:60:09": "Google", "d8:6c:63": "Google",
    "44:65:0d": "Amazon", "68:37:e9": "Amazon", "fc:a1:83": "Amazon",
    "00:1b:21": "Intel", "3c:97:0e": "Intel", "a0:88:b4": "Intel", "94:65:9c": "Intel",
    "00:15:5d": "Microsoft", "28:18:78": "Microsoft", "7c:1e:52": "Microsoft",
    "b8:27:eb": "Raspberry Pi", "dc:a6:32": "Raspberry Pi", "e4:5f:01": "Raspberry Pi",
    "50:c7:bf": "TP-Link", "60:e3:27": "TP-Link", "a4:2b:b0": "TP-Link",
    "20:e5:2a": "Netgear", "9c:3d:cf": "Netgear",
    "00:e0:fc": "Huawei", "48:46:fb": "Huawei", "64:09:80": "Xiaomi", "28:6c:07": "Xiaomi",
    "00:0c:29": "VMware", "00:50:56": "VMware", "24:0a:c4": "Espressif", "30:ae:a4": "Espressif",
    "04:18:d6": "Ubiquiti", "78:8a:20": "Ubiquiti", "00:1c:62": "LG", "fc:0f:e6": "Sony",
}

NAMES = {}                                    # ip -> label (None = looked up, no name found)
_resolving = set()                            # ips a worker is currently resolving
_pool = ThreadPoolExecutor(max_workers=4)


def is_local(ip):
    """True for RFC1918 / loopback / link-local addresses (v4 and v6)."""
    try:
        a = ip_address(ip)
        return a.is_private or a.is_loopback or a.is_link_local
    except ValueError:
        return False


def vendor(mac):
    """Hardware maker from a MAC's OUI (first 3 bytes), or None."""
    return OUI_VENDORS.get(mac[:8].lower()) if mac else None


def _resolve(ip):
    """Worker: LAN -> MAC vendor, external -> reverse DNS. Cache under LOCK (None caches a miss)."""
    if is_local(ip):
        with LOCK:
            label = vendor(STATE["macs"].get(ip)) or "LAN device"
    else:
        try:
            label = socket.gethostbyaddr(ip)[0]
        except (socket.herror, socket.gaierror, OSError):
            label = None
    with LOCK:
        NAMES[ip] = label
        _resolving.discard(ip)


def enrich(ips):
    """Queue resolution for any IPs not seen yet. Called off the sniffer thread (from the ws loop)."""
    with LOCK:
        todo = [ip for ip in ips if ip not in NAMES and ip not in _resolving]
        _resolving.update(todo)
    for ip in todo:
        _pool.submit(_resolve, ip)


def classify(pkt):
    """Protocol label via a mini dissector chain: app layer first, then transport."""
    if ARP in pkt:
        return "ARP"
    if DNS in pkt:
        return "DNS"
    for layer, fallback in ((TCP, "TCP"), (UDP, "UDP")):
        if layer in pkt:
            l = pkt[layer]
            return PORT_NAMES.get(l.dport) or PORT_NAMES.get(l.sport) or fallback
    if ICMP in pkt:
        return "ICMP"
    return pkt.name if pkt.name != "Ethernet" else "Other"


def parse(pkt):
    ip = pkt[IP] if IP in pkt else pkt[IPv6] if IPv6 in pkt else None
    src, dst = (ip.src, ip.dst) if ip else (getattr(pkt, "src", "?"), getattr(pkt, "dst", "?"))
    sport = dport = ""
    for layer in (TCP, UDP):
        if layer in pkt:
            sport, dport = pkt[layer].sport, pkt[layer].dport
            break
    return {
        "time": time.strftime("%H:%M:%S"),
        "src": f"{src}:{sport}" if sport else src,
        "dst": f"{dst}:{dport}" if dport else dst,
        "proto": classify(pkt),
        "len": len(pkt),
        "info": pkt.summary(),
    }


def on_packet(pkt):
    row = parse(pkt)
    with LOCK:
        row["id"] = STATE["next_id"]
        STATE["next_id"] += 1
        STATE["total_packets"] += 1
        STATE["total_bytes"] += row["len"]
        STATE["protocols"][row["proto"]] += 1
        src_ip = row["src"].rsplit(":", 1)[0]
        dst_ip = row["dst"].rsplit(":", 1)[0]
        STATE["talkers"][src_ip] += row["len"]
        STATE["edges"][(src_ip, dst_ip)] += row["len"]
        if Ether in pkt and is_local(src_ip):
            STATE["macs"][src_ip] = pkt[Ether].src  # sender's real MAC (only meaningful on our segment)
        RECENT.append(row)


@app.get("/")
def index():
    return FileResponse("static/index.html")


def origin_allowed(origin):
    """CSWSH guard: browsers always send Origin, so block any cross-site page from
    reading the live capture. None means a non-browser client (curl, python), not subject
    to the same-origin risk, so allow it. Host-only check ignores port (any local port is us)."""
    return origin is None or urlparse(origin).hostname in ("localhost", "127.0.0.1")


@app.websocket("/ws")
async def ws(sock: WebSocket):
    if not origin_allowed(sock.headers.get("origin")):
        await sock.close(code=1008)  # policy violation: cross-site WebSocket hijacking attempt
        return
    await sock.accept()
    with LOCK:
        last_id = STATE["next_id"]
        last_packets, last_bytes = STATE["total_packets"], STATE["total_bytes"]
    try:
        while True:
            await asyncio.sleep(1)
            with LOCK:
                new = [r for r in RECENT if r["id"] >= last_id]
                last_id = STATE["next_id"]
                edges = [[s, d, b] for (s, d), b in STATE["edges"].most_common(60)]
                talkers = STATE["talkers"].most_common(8)
                rel = {ip for s, d, _ in edges for ip in (s, d)} | {ip for ip, _ in talkers}
                snapshot = {
                    "pps": STATE["total_packets"] - last_packets,
                    "bps": STATE["total_bytes"] - last_bytes,
                    "total_packets": STATE["total_packets"],
                    "total_bytes": STATE["total_bytes"],
                    "protocols": dict(STATE["protocols"].most_common(8)),
                    "talkers": talkers,
                    "edges": edges,
                    "names": {ip: NAMES[ip] for ip in rel if NAMES.get(ip)},
                    "error": STATE["error"],
                    "packets": new[-100:],  # cap per tick; table doesn't need more
                }
                last_packets, last_bytes = STATE["total_packets"], STATE["total_bytes"]
            enrich(rel)  # off-lock: queue name lookups for IPs we don't know yet
            await sock.send_text(json.dumps(snapshot))
    except WebSocketDisconnect:
        pass


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--iface", default=None, help="interface to sniff (default: scapy's default)")
    ap.add_argument("--filter", default=None, help="BPF filter, e.g. 'tcp port 443'")
    ap.add_argument("--port", type=int, default=8000)
    args = ap.parse_args()

    sniffer = AsyncSniffer(prn=on_packet, store=False, iface=args.iface, filter=args.filter)
    try:
        sniffer.start()
        time.sleep(0.5)  # AsyncSniffer errors surface async; give it a beat
        # running stays True on failure; the dead thread + .exception are the real signal
        if not sniffer.thread.is_alive():
            raise sniffer.exception or RuntimeError("sniffer thread died")
    except Exception as e:
        STATE["error"] = (f"Capture failed: {e}. Install Npcap (npcap.com) and run this "
                          "script as Administrator.")
        print(STATE["error"])

    print(f"Dashboard: http://localhost:{args.port}")
    uvicorn.run(app, host="127.0.0.1", port=args.port, log_level="warning")


if __name__ == "__main__":
    main()

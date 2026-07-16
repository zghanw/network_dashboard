"""Local network monitor: Scapy capture -> FastAPI WebSocket -> live dashboard.

Run as Administrator (Npcap required on Windows): python main.py [--iface NAME] [--filter BPF]
"""
import argparse
import asyncio
import json
import threading
import time
from collections import Counter, deque
from urllib.parse import urlparse

import uvicorn
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse
from scapy.all import ARP, DNS, ICMP, IP, IPv6, TCP, UDP, AsyncSniffer

app = FastAPI()

LOCK = threading.Lock()
RECENT = deque(maxlen=500)  # rows for the live packet table
STATE = {
    "next_id": 0,
    "total_packets": 0,
    "total_bytes": 0,
    "protocols": Counter(),
    "talkers": Counter(),  # bytes per source IP
    "error": None,  # sniffer startup failure, shown in the UI
}

PORT_NAMES = {80: "HTTP", 8080: "HTTP", 443: "HTTPS", 22: "SSH", 25: "SMTP",
              123: "NTP", 1900: "SSDP", 5353: "mDNS", 3389: "RDP"}


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
        STATE["talkers"][src_ip] += row["len"]
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
                snapshot = {
                    "pps": STATE["total_packets"] - last_packets,
                    "bps": STATE["total_bytes"] - last_bytes,
                    "total_packets": STATE["total_packets"],
                    "total_bytes": STATE["total_bytes"],
                    "protocols": dict(STATE["protocols"].most_common(8)),
                    "talkers": STATE["talkers"].most_common(8),
                    "error": STATE["error"],
                    "packets": new[-100:],  # cap per tick; table doesn't need more
                }
                last_packets, last_bytes = STATE["total_packets"], STATE["total_bytes"]
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

# Network Monitor

[![Python 3.9+](https://img.shields.io/badge/Python_3.9+-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-009688?style=for-the-badge&logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com/)
[![Scapy](https://img.shields.io/badge/Scapy-1B6AC6?style=for-the-badge&logoColor=white)](https://scapy.net/)
[![SQLite](https://img.shields.io/badge/SQLite-003B57?style=for-the-badge&logo=sqlite&logoColor=white)](https://www.sqlite.org/)
[![Chart.js](https://img.shields.io/badge/Chart.js-FF6384?style=for-the-badge&logo=chartdotjs&logoColor=white)](https://www.chartjs.org/)
[![JavaScript](https://img.shields.io/badge/JavaScript-F7DF1E?style=for-the-badge&logo=javascript&logoColor=black)](https://developer.mozilla.org/docs/Web/JavaScript)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg?style=for-the-badge)](LICENSE)

A local, real-time network monitor and blue-team console. It captures live traffic on your own segment with Scapy, streams it to a single-page dashboard over a WebSocket, and turns raw packets into situational awareness: a live connection graph, heuristic threat detection, enriched host names and geolocation, and a persisted timeline you can scrub back through.

> **Local-first and offline.** The server binds to `127.0.0.1`, reads only your own segment, and keeps every byte on-device. No cloud, no account, no telemetry. The one optional network fetch is a free offline GeoIP database you download once.

## Screenshots

_Live captures go in [`assets/`](assets/). Recommended: the Overview tab, the connection Graph, the Alerts feed, and the History timeline scrubber._

**Overview**
![Overview tab](assets/screenshot_overview.png)

**Connection Graph**
![Connection graph](assets/screenshot_graph.png)

**Alerts and History replay**
![Alerts and history](assets/screenshot_alerts_history.png)

---

## Table of Contents

1. [Overview](#overview)
2. [Tech Stack](#tech-stack)
3. [System Architecture](#system-architecture)
4. [Features](#features)
5. [Setup and Installation](#setup-and-installation)
6. [Security](#security)
7. [Testing](#testing)
8. [Project Structure](#project-structure)
9. [Design Decisions](#design-decisions)
10. [License](#license)

---

## Overview

Most network visibility tools are either heavyweight (a full SIEM), cloud-bound (your traffic leaves the machine), or packet-level only (Wireshark shows you every frame but never tells you a host is scanning you). This project sits in the gap: a lightweight, fully local console that answers "what is happening on my network right now, and what just happened" at a glance.

**What it does:**

- Captures packets on the selected interface with Scapy's `AsyncSniffer` and streams a one-second snapshot to the browser over a WebSocket.
- Draws a live force-directed connection graph of who is talking to whom, with your own devices in green and external hosts in blue.
- Runs a small detection engine on the capture path (port scan, ARP spoofing, DNS anomaly, new device) and surfaces alerts with tunable thresholds.
- Enriches raw IPs off the hot path: LAN devices by MAC vendor (OUI), external hosts by reverse DNS, and any host by offline GeoIP country.
- Aggregates packets into connections (the 5-tuple) and persists a per-second metrics timeline plus alerts to SQLite, so you can scrub back through history and replay what happened.

---

## Tech Stack

| Layer | Tools |
|---|---|
| Capture | Scapy (`AsyncSniffer`), Npcap |
| Backend | Python 3.9+, FastAPI, Uvicorn |
| Persistence | SQLite (standard library, WAL mode) |
| Enrichment | MAC OUI table, reverse DNS, DB-IP Lite (offline GeoIP) |
| Frontend | Vanilla HTML/CSS/JS, Chart.js, force-graph (no build step) |
| Transport | WebSocket (live snapshots), REST (history) |

---

## System Architecture

```
Local network segment
       |  raw capture (Npcap + Scapy AsyncSniffer, run as Administrator)
FastAPI backend  (127.0.0.1:8000)
  |- Parser + classifier   ->  per-packet rows, protocol labels
  |- Detectors             ->  port scan, ARP spoof, DNS anomaly, new device
  |- Enrichment (threads)  ->  MAC vendor (OUI), reverse DNS, offline GeoIP
  |- Flow aggregation      ->  5-tuple connections
  |- History sampler       ->  SQLite (per-second metrics + alerts, WAL, 24h retention)
  |- WebSocket  /ws         ->  1s snapshots, Origin-guarded
  `- REST       /history    ->  persisted timeline for replay
       |  WebSocket + REST (same-origin only)
Browser dashboard  (single static file, Chart.js + force-graph, no build step)
  Overview  |  Graph  |  Alerts  |  Flows  |  History
```

**Key design choices:**

- **No build step.** The entire frontend is one `static/index.html` with two CDN libraries. Clone and run.
- **No database server.** History is a single SQLite file written by one background thread in WAL mode; reads use their own connection.
- **Detection lives on the capture path.** `on_packet` is the one choke point every packet flows through, so detectors attach there and keep tunable, time-windowed state.
- **Enrichment never blocks capture.** Reverse DNS runs in a thread pool off both the sniffer and the socket loop, and results are cached.
- **Everything stays on the host.** Bound to localhost, offline by design, and the WebSocket rejects cross-site connections.

---

## Features

### Overview

At-a-glance KPIs (packets/sec, bandwidth, peak PPS, active hosts, totals), a rolling throughput chart, a protocol-mix breakdown, top talkers by volume, and a live packet feed with substring filtering and a pause control for freezing the stream to inspect it.

### Connection Graph

A live force-directed graph where every device is a node and every conversation is a moving edge. Local hosts render green, external hosts blue, and any host that triggers a detection turns red. Nodes are labeled by vendor or hostname and tagged with a country code when the GeoIP database is installed.

### Detection Engine (Alerts)

Four heuristic detectors run on live traffic, each a small testable function with thresholds exposed as constants in `detectors.py`:

- **Port scan** - one source touching many distinct host/port targets inside a time window.
- **ARP spoofing** - an IP whose advertised MAC suddenly changes (classic man-in-the-middle).
- **DNS anomaly** - absurdly long query names, a signal of exfiltration or domain-generation traffic.
- **New device** - the first sighting of a local host after a baseline warm-up.

Alerts appear in a severity-colored feed with a live count badge on the tab, and the offending host lights up on the graph.

### Flows

Packets aggregated into connections keyed by the direction-canonical 5-tuple, shown as a table of protocol, endpoints, packet count, bytes, and duration.

### History and Timeline Replay

A background sampler writes one metrics row per second plus every alert to SQLite (WAL mode, 24-hour retention). The History tab charts throughput over a selectable range (30 minutes to 24 hours) and provides a timeline scrubber: drag it and read back the exact throughput, packet rate, and alert count at any past second, alongside the alerts that fired in that window. History survives restarts.

---

## Setup and Installation

### Prerequisites

- **Python 3.9+**
- **A packet-capture driver:**
  - Windows: [Npcap](https://npcap.com/), installed with "WinPcap API-compatible mode" enabled.
  - macOS / Linux: libpcap (usually preinstalled, otherwise available via your package manager).
- **Elevated privileges** - raw capture requires Administrator on Windows or `sudo` on macOS/Linux.

### Install

```bash
git clone https://github.com/zghanw/network_dashboard.git
cd network_dashboard
pip install -r requirements.txt
```

### Run

Launch with elevated privileges (raw capture requires it), then open the printed URL:

```bash
# Windows (Administrator terminal)
python main.py

# macOS / Linux
sudo python main.py
```

Then visit **http://localhost:8000**.

Optional flags:

```bash
python main.py --iface "Wi-Fi"        # choose a capture interface
python main.py --filter "tcp port 443" # BPF capture filter
python main.py --port 8080             # change the dashboard port
```

### Optional: enable GeoIP

Country labels are dormant until you drop in a free database (no account required):

1. Download the "IP to Country Lite" CSV from [db-ip.com](https://db-ip.com/db/download/ip-to-country-lite).
2. Decompress it to `data/dbip-country-lite.csv`.

Without it, everything else works and external nodes simply show no country.

---

## Security

This tool runs with high privilege and parses untrusted input, so it is built defensively:

- **Cross-Site WebSocket Hijacking guard.** `/ws` validates the `Origin` header and rejects any cross-site page, so a website you visit cannot read your capture.
- **Localhost only.** The server binds to `127.0.0.1`; it is never exposed to the network.
- **Untrusted packet data.** Packet fields are attacker-influenced and are HTML-escaped before rendering.
- **Pinned dependencies.** `requirements.txt` pins exact versions for reproducible installs.
- **Offline by default.** No outbound calls beyond the reverse-DNS lookups your resolver already makes.

---

## Testing

Assert-based self-checks that run without Npcap or Administrator:

```bash
python test_parse.py       # parser, protocol classify, Origin guard, MAC vendor, flow key
python test_detectors.py   # port scan, ARP spoof, DNS anomaly detectors
python test_geoip.py       # offline IP-to-country range lookup
python test_history.py     # SQLite persistence, query window, retention
```

---

## Project Structure

```
├── main.py            # FastAPI app: capture, WebSocket, snapshot builder, enrichment
├── detectors.py       # port scan / ARP spoof / DNS anomaly / new-device detectors
├── geoip.py           # offline IP -> country lookup (DB-IP Lite)
├── history.py         # SQLite persistence + /history query (background sampler)
├── static/
│   └── index.html     # single-file dashboard (vanilla JS, Chart.js + force-graph)
├── test_parse.py
├── test_detectors.py
├── test_geoip.py
├── test_history.py
├── requirements.txt   # pinned: scapy, fastapi, uvicorn
└── .gitignore
```

---

## Design Decisions

- **Vanilla over a framework.** One real-time page with no routing or shared state does not justify a build toolchain. The frontend is a single static file plus Chart.js and force-graph from a CDN.
- **A tab shell, not a rewrite.** The dashboard grew feature by feature (Overview, then Graph, Alerts, Flows, History) as independent modules behind one tab bar, so each ships and demos on its own.
- **Persistence decoupled from clients.** The history sampler samples live state on its own thread, so the timeline keeps building even with no browser open.
- **Restraint by intent.** The interface deliberately avoids the generic "AI dashboard" look: flat surfaces, no glow, one accent color used only where it carries meaning, and monospace for every value.

---

## License

Released under the [MIT License](LICENSE).

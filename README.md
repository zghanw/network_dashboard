# Network Dashboard

[![Python](https://img.shields.io/badge/Python-3.8+-3776AB?style=flat-square&logo=python&logoColor=white)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115.13-005571?style=flat-square&logo=fastapi)](https://fastapi.tiangolo.com/)
[![Scapy](https://img.shields.io/badge/Scapy-2.7.0-002F6C?style=flat-square)](https://scapy.net/)
[![Uvicorn](https://img.shields.io/badge/Uvicorn-0.34.3-3949ab?style=flat-square)](https://www.uvicorn.org/)
[![Chart.js](https://img.shields.io/badge/Chart.js-4-FF6384?style=flat-square&logo=chartdotjs&logoColor=white)](https://www.chartjs.org/)

Network Dashboard is a real-time local network traffic monitor and analyzer. It captures network packets using Scapy, processes them to extract metadata, and streams the updates to a responsive web console using FastAPI WebSockets. The frontend displays live traffic metrics and visualizations.

## Features

- Real-time packet sniffing and classification for common protocols.
- Live dashboard visualizing packets per second, throughput, and active hosts.
- Interactive charts showing protocol distribution and throughput trends over time.
- Dynamic table displaying the latest captured packets with search filtering.
- Pause option to freeze the packet feed while maintaining background statistics.
- Host-level security with Same-Origin checks for WebSocket connections.

## Prerequisites

- Python 3.8 or higher.
- Administrator privileges (required to sniff network interfaces).
- **Windows**: Npcap (install from the official Npcap website and select WinPcap compatibility mode).
- **macOS/Linux**: libpcap (pre-installed or available via package managers).

## Installation

1. Clone or download the project files.
2. Install the required Python dependencies:
   ```bash
   pip install -r requirements.txt
   ```

## Usage

Start the backend server by running the command with administrator or root privileges:

- **Windows** (PowerShell or Command Prompt as Administrator):
  ```cmd
  python main.py
  ```
- **macOS/Linux**:
  ```bash
  sudo python main.py
  ```

Open your browser and navigate to the dashboard at:
```
http://localhost:8000
```

### CLI Arguments

You can customize the capture behavior using command line flags:
- `--iface`: Specify the network interface name (defaults to Scapy's default interface).
- `--filter`: Apply a Berkeley Packet Filter (BPF) string (e.g., `tcp port 443` or `udp port 53`).
- `--port`: Port number to run the FastAPI server (defaults to 8000).

## Architecture

- **Backend**: Python, FastAPI (ASGI web framework), Uvicorn (web server), Scapy (packet capturing and dissection).
- **Frontend**: HTML5, CSS3, JavaScript (ES6+), Chart.js (data visualization).

"""Offline IP -> country lookup.

Reads a DB-IP "IP to Country Lite" CSV if present at data/dbip-country-lite.csv, builds
sorted range tables once, and answers lookups with a binary search. No file => every lookup
returns None (the feature is simply dormant, nothing breaks).

Enable it (free, monthly, no account needed):
  1. Download the CSV: https://db-ip.com/db/download/ip-to-country-lite
  2. gunzip it into  data/dbip-country-lite.csv
CSV rows are  start_ip,end_ip,country_code  (mixed IPv4 and IPv6). ponytail: swap in a
richer city DB later if you want more than country.
"""
import bisect
import csv
import os
from ipaddress import ip_address

DB_PATH = "data/dbip-country-lite.csv"

_v4_starts, _v4_ranges = [], []   # parallel: sorted start ints  /  (end_int, country)
_v6_starts, _v6_ranges = [], []
_loaded = False


def _load():
    global _loaded
    _loaded = True
    if not os.path.exists(DB_PATH):
        return
    v4, v6 = [], []
    with open(DB_PATH, newline="", encoding="utf-8") as f:
        for row in csv.reader(f):
            if len(row) < 3:
                continue
            try:
                start, end = ip_address(row[0]), ip_address(row[1])
            except ValueError:
                continue
            (v4 if start.version == 4 else v6).append((int(start), int(end), row[2]))
    v4.sort()
    v6.sort()
    _v4_starts[:] = [s for s, _, _ in v4]
    _v4_ranges[:] = [(e, c) for _, e, c in v4]
    _v6_starts[:] = [s for s, _, _ in v6]
    _v6_ranges[:] = [(e, c) for _, e, c in v6]


def country(ip):
    """Two-letter country code for an IP, or None (bad IP / no DB / unlisted range)."""
    if not _loaded:
        _load()
    try:
        addr = ip_address(ip)
    except ValueError:
        return None
    starts, ranges = (_v4_starts, _v4_ranges) if addr.version == 4 else (_v6_starts, _v6_ranges)
    if not starts:
        return None
    n = int(addr)
    i = bisect.bisect_right(starts, n) - 1   # last range whose start <= n
    if i < 0:
        return None
    end, cc = ranges[i]
    if n > end or cc == "ZZ":   # ZZ = reserved / unknown; treat as no country
        return None
    return cc

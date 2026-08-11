"""Persist a per-second metrics time-series + alerts to SQLite, so history survives restarts
and the History tab can chart it and scrub back through time.

One background thread owns the write connection (no cross-thread SQLite surprises); reads open
their own short-lived connection. WAL mode keeps reads from blocking the writer.
"""
import sqlite3
import threading
import time
from collections import deque

DB_PATH = "history.db"
RETAIN_HOURS = 24               # older metrics rows are pruned each tick

_db = None
_pending = deque()             # alerts awaiting write: (ts, sev, kind, msg, src)
_pending_lock = threading.Lock()


def record_alert(a):
    """Called from the capture thread when a detector fires; queued for the writer."""
    with _pending_lock:
        _pending.append((a["ts"], a["sev"], a["kind"], a["msg"], a.get("src") or ""))


def _connect(path):
    db = sqlite3.connect(path)
    db.execute("PRAGMA journal_mode=WAL")
    db.execute("CREATE TABLE IF NOT EXISTS metrics "
               "(ts INTEGER PRIMARY KEY, pps INTEGER, bps INTEGER, packets INTEGER, bytes INTEGER, alerts INTEGER)")
    db.execute("CREATE TABLE IF NOT EXISTS alerts (ts REAL, sev TEXT, kind TEXT, msg TEXT, src TEXT)")
    db.commit()
    return db


def run_sampler(get_totals):
    """Loop forever: once a second, write one metrics row (deltas since last tick) plus any
    queued alerts, then prune old rows. get_totals() -> (total_packets, total_bytes, total_alerts)."""
    global _db
    _db = _connect(DB_PATH)
    last_p = last_b = 0
    while True:
        time.sleep(1)
        packets, byts, alert_total = get_totals()
        pps, bps = max(0, packets - last_p), max(0, byts - last_b)
        last_p, last_b = packets, byts
        ts = int(time.time())
        with _pending_lock:
            pend = list(_pending)
            _pending.clear()
        try:
            _db.execute("INSERT OR REPLACE INTO metrics VALUES (?,?,?,?,?,?)",
                        (ts, pps, bps, packets, byts, alert_total))
            if pend:
                _db.executemany("INSERT INTO alerts VALUES (?,?,?,?,?)", pend)
            _db.execute("DELETE FROM metrics WHERE ts < ?", (ts - RETAIN_HOURS * 3600,))
            _db.commit()
        except sqlite3.Error:
            pass   # persistence is best-effort; a DB hiccup must never stall capture


def query(minutes):
    """Return the persisted time-series + alerts for the last `minutes`, for the History tab."""
    since = int(time.time()) - minutes * 60
    db = _connect(DB_PATH)
    try:
        metrics = [{"ts": r[0], "pps": r[1], "bps": r[2], "alerts": r[3]}
                   for r in db.execute("SELECT ts,pps,bps,alerts FROM metrics WHERE ts>=? ORDER BY ts", (since,))]
        alerts = [{"ts": r[0], "sev": r[1], "kind": r[2], "msg": r[3], "src": r[4]}
                  for r in db.execute("SELECT ts,sev,kind,msg,src FROM alerts WHERE ts>=? ORDER BY ts DESC LIMIT 200", (since,))]
    finally:
        db.close()
    return {"metrics": metrics, "alerts": alerts}

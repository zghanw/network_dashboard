"""Self-check for history persistence + query. Uses a temp DB: python test_history.py"""
import os
import tempfile
import time

import history

history.DB_PATH = os.path.join(tempfile.mkdtemp(), "test-history.db")
now = int(time.time())

db = history._connect(history.DB_PATH)
db.execute("INSERT INTO metrics VALUES (?,?,?,?,?,?)", (now, 10, 2000, 100, 5000, 3))
db.execute("INSERT INTO metrics VALUES (?,?,?,?,?,?)", (now - 3600, 1, 1, 1, 1, 0))  # an hour old
db.execute("INSERT INTO alerts VALUES (?,?,?,?,?)", (now, "high", "Port scan", "x probed 20", "10.0.0.5"))
db.commit()
db.close()

out = history.query(30)   # last 30 minutes
assert len(out["metrics"]) == 1, out            # the hour-old row is outside the window
assert out["metrics"][0]["bps"] == 2000, out
assert len(out["alerts"]) == 1 and out["alerts"][0]["kind"] == "Port scan", out

history._pending.clear()
history.record_alert({"ts": now, "sev": "low", "kind": "New device", "msg": "m", "src": "10.0.0.9"})
assert len(history._pending) == 1, history._pending

print("all history checks passed")

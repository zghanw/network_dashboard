"""Self-check for the offline GeoIP range lookup. Uses a synthetic CSV: python test_geoip.py"""
import os
import tempfile

import geoip

_csv = "1.0.0.0,1.0.0.255,US\n2.0.0.0,2.255.255.255,GB\n2001:200::,2001:200:ffff:ffff:ffff:ffff:ffff:ffff,JP\n"
_f = tempfile.NamedTemporaryFile("w", suffix=".csv", delete=False, newline="")
_f.write(_csv)
_f.close()

geoip.DB_PATH = _f.name
geoip._loaded = False   # force a reload against the fixture

assert geoip.country("1.0.0.128") == "US", "v4 inside first range"
assert geoip.country("2.1.2.3") == "GB", "v4 inside a wide range"
assert geoip.country("2001:200::1") == "JP", "v6 inside range"
assert geoip.country("9.9.9.9") is None, "v4 outside every range"
assert geoip.country("3.3.3.3") is None, "v4 in a gap between ranges"
assert geoip.country("not-an-ip") is None, "garbage input"

os.unlink(_f.name)
print("all geoip checks passed")

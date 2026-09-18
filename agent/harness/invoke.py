"""Executed in a disposable trusted container on the candidate's internal network.

Docker does not publish ports from `--internal` networks, so the smoke request is sent from
inside the network instead of opening any path between the candidate and the host.
"""

import json
import sys
import time
import urllib.request

URL = "http://candidate:8080/2015-03-31/functions/function/invocations"
MARKER = "FIRST_COMMIT_RESPONSE "

with open("/opt/event.json", "rb") as handle:
    event = handle.read()
deadline = time.monotonic() + float(sys.argv[1])
body = None
while time.monotonic() < deadline:
    request = urllib.request.Request(URL, event, {"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(request, timeout=15) as response:
            body = response.read(65537)
        break
    except OSError:
        time.sleep(0.25)
if body is None:
    raise SystemExit(3)
if len(body) > 65536:
    raise SystemExit(4)
print(MARKER + json.dumps(json.loads(body), sort_keys=True))

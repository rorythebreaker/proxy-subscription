# Proxy subscription

Public SOCKS5 and VLESS + REALITY subscriptions, refreshed on the five-minute
schedule `2-59/5 * * * *`. GitHub Actions may delay scheduled runs.

- `public/all.txt`: deduplicated union of the current protocol lists.
- `public/proxies.txt`: SOCKS5 share URIs (`socks://host:port#CC%20host`).
- `public/vless.txt`: VLESS + REALITY share URIs, with the same country/host labels.
- `public/status.json`, `public/protocol_status.json`, `public/combined_status.json`:
  attempt time, source success time, actual publication counts and check outcomes.
- `public/socks_state.json`, `public/vless_state.json`: per-node verification times.

## Filtering

SOCKS5 retains the existing policy: HTTPS reachability, latency <= 3500 ms and
payload throughput >= 0.25 Mbps. Transfers have total time and size limits.

VLESS uses **connectivity only**, with **no speed or latency cutoff**. The pinned
sing-box 1.14.4 validates each generated configuration and opens a local SOCKS
listener. HTTPS must succeed through the full VLESS/REALITY tunnel. If the first
probe fails, a second independent target is tried. Both test targets must be
reachable directly from the runner before nodes can be marked unreachable.

- `passed`: HTTPS 204 through the tunnel; the node is published.
- `unreachable`: network attempts to both healthy targets failed; the node is removed.
- `inconclusive`: HTTP rejection, unhealthy test targets or verifier failure;
  a previously verified node can survive within its original cache TTL.
- `unsupported`: transport or connection parameters cannot be faithfully mapped;
  the node is not described as dead and a new unverified node is not published.
- `invalid`, `config_error:*`, `runtime_error:*`: separate validation/engine outcomes.
- `not_tested`: the bounded checking window ended. New untested nodes are not published.

TCP/raw, WebSocket, gRPC (gun), HTTP/H2 and HTTPUpgrade are mapped explicitly.
XHTTP, TCP header obfuscation and non-`none` VLESS encryption are unsupported by
this verifier. Unknown connection parameters are not silently discarded.
Missing TLS fingerprints default to `chrome` in both the checked and published URI.
Shadowsocks collection/code and its obsolete published file are removed.

Up to 1000 unique VLESS candidates are collected, round-robin across the existing
six sources. Up to 240 candidates are selected per run with a rotating starting
point. Work stops scheduling checks near the stage deadline, so the actual count
can be smaller. Recent cached nodes can accumulate across batches. Counts in the
status files distinguish candidates, network tests, outcomes and published nodes.

## Freshness and failures

Only records verified within `STALE_TTL_SECONDS` (default **1800 seconds / 30
minutes**) can enter any output. Keeping a cached node does **not** renew its
verification time. Explicit network failures remove it immediately. Source
outages trigger rechecks of recent cached nodes; legacy files without verification
metadata are not treated as verified. A node can outlive an upstream outage only
by passing a new connectivity check.

Empty HTTP bodies are valid empty sources. HTML, corrupt base64 and unrecognized
nonempty payloads are source failures, not successful empty updates. Recognition
of a mixed protocol subscription does not require it to contain VLESS records.

Each collector writes to a temporary staging directory. The wrapper kills an
entire process group when a stage exceeds its deadline (120 s SOCKS, 145 s VLESS),
keeps only unexpired previous results and assembles the final output after both
attempts. Publication is one Git commit. An engine installation failure cannot
block the SOCKS update. Concurrent changes to collector code prevent old calculated
results from being rebased and published over new settings.

## Running

Requires Python 3.12, curl, `pip install -r requirements.txt`, and the pinned
sing-box binary on PATH. GeoIP is optional metadata; lookup failures use `ZZ`.

```sh
python -m unittest discover -s tests -v
python refresh.py
```

`MAX_PROTOCOL_NODES`, `MAX_PROTOCOL_CHECKS`, `PROTOCOL_WORKERS`,
`STALE_TTL_SECONDS`, `SOCKS_STAGE_SECONDS`, `VLESS_STAGE_SECONDS` and `OUTPUT_DIR`
can be set in the environment. SOCKS thresholds retain their existing environment
variables. Raising the batch size does not override stage deadlines.

A successful probe establishes availability **from the GitHub runner at check
time**. Availability from a different network can differ.

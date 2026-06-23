# Murmur

Decoy traffic generator for a Raspberry Pi Zero 2 W. Plug it into your
router (preferably which already runs Pi-hole) and it quietly emits plausible decoy
traffic so your ISP and the data brokers buying their logs can't cleanly
profile what your household is actually interested in.

It works at the **network layer**. It muddies the three things a passive
observer can see — the domains you look up, the destinations you connect to,
and the shape/volume/timing of your traffic — by burying your real activity in
a crowd of plausible decoys.

## What it does and doesn't do

| Threat | Status |
|---|---|
| ISP / data-broker interest profiling | **disrupted** — your profile is buried in decoys |
| A targeted attacker reading ISP logs | **hardened** — un-mixing is made expensive, not impossible |
| Account-level tracking (Google, Meta) | not covered — those tie to your login, not your IP |
| Anonymity (hiding *that it's you*) | not covered — use a VPN or Tor for that |

This is honest cost-raising against bulk and commercial surveillance, not an
invisibility cloak. It does **not** execute JavaScript; everything it fakes is
what the ISP can actually see through the encryption.

## Two layers

- **DNS layer** — constant lightweight lookups to popular real domains, shaped
  to a household rhythm and quiet overnight. These go to your router's Pi-hole
  (the LAN resolver), so they land in the *same* query log as real traffic.
  Costs well under 1 GB/month.
- **Browser layer** — scheduled shallow page loads using a browser-impersonated
  TLS fingerprint (`curl_cffi`). Each session follows a couple of same-site
  links with real referers and fetches a sample of each page's assets, creating
  the realistic destination fan-out and byte volumes of a real visit. This is
  the bandwidth-heavy layer; it self-throttles near your monthly cap.

## Requirements

- Raspberry Pi Zero 2 W (or anything better)
- **64-bit Raspberry Pi OS Lite** (Bookworm) — gives you prebuilt `curl_cffi`
  wheels so install is fast and needs no compiler
- Wired or Wi-Fi connection to your GL.iNet router; the Pi just needs to be a
  normal LAN client that uses the router's Pi-hole for DNS (the default)

## Install

```bash
git clone <this repo> murmur && cd murmur
sudo ./install.sh
```

The installer creates a `murmur` service user, sets up a venv, detects your
router (default gateway) as the resolver, installs a systemd service, and
starts it. When it finishes it prints the dashboard URL.

Open **`http://<pi-ip>:8787`** on any device on your network.

## Using the dashboard

- **Blend Score** + the swarm show how separable your real device is from the
  noise. Every factor is computed live from this node.
- The **fix buttons** are real:
  - *Match Windows TTL* — applies an nftables rule so the Pi's packets don't
    fingerprint as Linux (runs via a locked-down sudoers entry for one script)
  - *Enable IPv6 noise* — turns on AAAA lookups / v6 decoys
  - *Refresh seed list* — resets the fetch-health window and reloads seeds
- **Switch to DoH** is informational — encrypted DNS is a router-side change.

## Configuration

Edit `/etc/murmur/config.json` then `sudo systemctl restart murmur`.

Key knobs:

- `resolver` — `"auto"` uses the default gateway (your Pi-hole). Set an IP to
  override. If your household uses encrypted DNS to a third party, point this
  at the *same* provider, or the noise won't blend.
- `dns_layer.base_qpm` — baseline DNS queries per minute (scaled by rhythm).
- `browser_layer.active_start/end` — waking-hours window for the heavy layer.
- `browser_layer.asset_sample` / `max_assets` — how much of each page's asset
  fan-out to fetch. Lower = less realistic but less bandwidth.
- `bandwidth.monthly_cap_gb` / `throttle_at_pct` — the governor. The browser
  layer suspends itself (DNS layer keeps running) past the threshold.
- `impersonate` — TLS fingerprints to rotate through. For best blending, set
  this to match the browsers your household actually uses.

## Notes & honest limits

- The **swarm's "real flow" dots are illustrative** — this node can't see your
  other devices' traffic, so it can't plot your actual flows. Separability is
  derived from the measured score factors.
- The **factor point weights are reasonable defaults, not measured** — turning
  them into a defensible model is real research, not a setting.
- Pi-hole will block decoy sub-resource fetches to ad/tracker domains, exactly
  as it does for your real browsers. That's fine — it makes the decoy device
  behave like a real device behind the same Pi-hole.
- All metrics stay **local** to the Pi (SQLite, pruned to a few days). Nothing
  leaves the device. The Pi becomes a record of activity, so treat it as
  sensitive: keep the dashboard on your LAN only.

## Service

```bash
journalctl -u murmur -f          # logs
sudo systemctl restart murmur    # after config changes
sudo systemctl disable --now murmur   # stop & disable
```

## Layout

```
murmur.py        engine: DNS layer, browser layer, scheduler, SQLite
dashboard.py     stdlib HTTP server: console UI + live JSON API + fixes
static/index.html  the console
seeds.json       categorized popular domains (the decoy pool)
config.json      defaults (installed to /etc/murmur/config.json)
harden-ttl.sh    nftables/iptables TTL normaliser
install.sh       plug-and-play installer
murmur.service   systemd unit
```

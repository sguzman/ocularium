# Ocularium

A local-first **Rust + egui desktop application** for discovering and eventually viewing IP cameras on your own network.

> Status: **0.1.x discovery and device inspection milestone.** The first release inventories LAN devices and identifies camera candidates. It does **not** yet decode video, recover proprietary cloud streams, or verify that an accessible RTSP *video feed* exists.

## Why

Household cameras often come from different manufacturers and require different mobile apps. Ocularium begins by asking the network which devices exist, rather than requiring users to know camera brands or IP addresses in advance.

## Run on Linux

Install the standard Rust toolchain and Linux graphical build dependencies, then:

```bash
cargo run --release
```

Ocularium is a native application; it needs **no server**, no cloud login, and no root privileges. It does need network access to your own LAN.

## Discovery in v0.1

- Enumerates non-loopback IPv4 interfaces and offers one **/24 scan scope** at a time.
- Sends an ONVIF WS-Discovery multicast probe (UDP 3702).
- Sends a UPnP/SSDP M-SEARCH multicast probe (UDP 1900).
- Uses interface-bound mDNS multicast to discover advertised RTSP, ONVIF, and related services (UDP 5353).
- Checks selected TCP service ports across the chosen local /24 using bounded workers.
- Performs a light RTSP OPTIONS handshake on responding RTSP ports.
- Reads limited unauthenticated HTTP headers and HTML titles from selected open local ports; no credentials, redirects, or cloud access.
- Looks up MAC manufacturers using installed local OUI databases; locally administered/randomized addresses are labeled rather than assigned fabricated vendors.
- Offers a **Copy report** button containing scan results and device evidence.
- Saves optional user-authored device labels in `$XDG_DATA_HOME/ocularium/registry.json` (or `~/.local/share/ocularium/registry.json`). Labels use MAC identity where present, falling back to IP addresses; discovery results and camera credentials are **not** persisted.
- Provides an on-demand **Inspect RTSP** button on detected port 554/8554 devices. The tool sends RTSP OPTIONS and DESCRIBE requests to `/`, reports server/authentication hints and SDP codecs if present. It never guesses stream paths or attempts credentials.
- Displays found IPs, detected services, advertised ONVIF addresses/scopes, SSDP headers, and Linux neighbor-table MACs when available.
- Distinguishes confirmed protocol responses from **possible camera** classifications.
- Supports cancellation, filtering by metadata, and a copyable report. Nothing is uploaded externally.

This is a discovery tool, **not** a vulnerability scanner: no password guessing, RTSP path brute forcing, unauthorized credential extraction, or exploitation. Scan networks you own or are authorized to administer.

### Limitations

- Discovery is limited to the selected IPv4 /24, not the whole LAN or multiple VLANs.
- Wi-Fi client isolation, mesh/router VLANs, multicast filtering, and local firewalls can hide devices.
- Cloud-only cameras may appear as generic TCP devices or not appear at all.
- A reachable TCP port or RTSP handshake does **not** prove a playable video stream.
- MAC addresses are best-effort on Linux; manufacturer lookup requires an existing local vendor database, such as `/usr/share/hwdata/oui.txt`, `/usr/share/ieee-data/oui.txt`, or `/usr/share/nmap/nmap-mac-prefixes`. Missing vendor data is non-fatal. Do not install paid software.
- mDNS can be blocked by multicast filtering or socket conflicts; scan warnings explain failures.
- HTTP titles or RTSP port presence are only identification clues, never proof of accessible video.
- Camera access credentials, verified playback, recording, snapshots, and MCP are later milestones.
- Even when RTSP returns an SDP description, this is **not** proof that RTP media packets can be received or decoded.
- RTSP inspection tests only the root (`/`) path; 404 does not mean a camera cannot stream elsewhere. No redirects or authentication attempts are performed.

## Architecture

The `discovery`, `mdns`, and `rtsp` modules perform network I/O on background threads and communicate over channels. The `app` module renders the egui interface and never blocks the UI with sockets. No server process is required.

See [ROADMAP.md](ROADMAP.md) for planned stages.

## Quality

```bash
cargo fmt --all -- --check
cargo test --all-targets
cargo clippy --all-targets -- -D warnings
```

CI performs these checks on Linux. Real camera discovery requires manual testing on the target LAN; CI cannot substantiate real hardware results.

## Security

Ocularium runs locally and stores no credentials in v0.1. Future streaming and MCP access must require deliberate authorization, with credentials held by the local application rather than returned to AI agents.

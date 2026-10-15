# Ocularium

A local-first **Rust + egui desktop application** for discovering and eventually viewing IP cameras on your own network.

> Status: **0.1.0 discovery milestone.** The first release inventories LAN devices and identifies camera candidates. It does **not** yet decode video, recover proprietary cloud streams, or verify that an accessible RTSP *video feed* exists.

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
- Checks selected TCP service ports across the chosen local /24 using bounded workers.
- Performs a light RTSP OPTIONS handshake on responding RTSP ports.
- Displays found IPs, detected services, advertised ONVIF addresses/scopes, SSDP headers, and Linux neighbor-table MACs when available.
- Distinguishes confirmed protocol responses from **possible camera** classifications.
- Supports cancellation and filtering. Nothing is uploaded externally.

This is a discovery tool, **not** a vulnerability scanner: no password guessing, RTSP path brute forcing, unauthorized credential extraction, or exploitation. Scan networks you own or are authorized to administer.

### Limitations

- Discovery is limited to the selected IPv4 /24, not the whole LAN or multiple VLANs.
- Wi-Fi client isolation, mesh/router VLANs, multicast filtering, and local firewalls can hide devices.
- Cloud-only cameras may appear as generic TCP devices or not appear at all.
- A reachable TCP port or RTSP handshake does **not** prove a playable video stream.
- MAC addresses are best-effort on Linux and manufacturer inference is not implemented yet.
- Camera access credentials, playback, recording, snapshots, and MCP are later milestones.

## Architecture

The `discovery` module performs network I/O on background threads and communicates over channels. The `app` module renders the egui interface and never blocks the UI with sockets. No server process is required.

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

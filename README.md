# Ocularium

A local-first **Rust + egui desktop application** for discovering and eventually viewing IP cameras on your own network.

> Status: **0.1.x discovery and device inspection milestone.** The app inventories LAN devices and camera candidates. It now offers an optional local CPU-decoded **single RTSP frame** experiment using the installed `ffmpeg` executable, but no continuous video playback, authenticated snapshot decoding, or verified household camera frames yet.

## Why

Household cameras often come from different manufacturers and require different mobile apps. Ocularium begins by asking the network which devices exist, rather than requiring users to know camera brands or IP addresses in advance.

## Run on Linux

Install the standard Rust toolchain and Linux graphical build dependencies, then:

```bash
cargo run --release
```

Ocularium is a native application; it needs **no server**, no cloud login, and no root privileges. It does need network access to your own LAN.

## Experimental single-frame RTSP capture

Select an RTSP-capable discovered device and enter its **exact stream path** (no endpoint guessing). Click **Capture one frame :PORT**. If the local `ffmpeg` executable is installed, Ocularium runs it in a bounded worker to attempt CPU decoding of a single 640 × 360 RGB frame, shown as an in-memory egui texture. Capture is manually triggered, runs at most 12 seconds, and never records, uploads, saves, or includes image pixels in reports.

Capture is **unauthenticated**. The username and password fields are used only by **Test RTSP access**, not by frame capture; no camera credentials are put into subprocess arguments. Streams requiring authentication, proprietary transport, or an unknown RTSP path may fail. A successful OPTIONS or DESCRIBE response does not prove video can be decoded.

Normal discovery, scanning, and RTSP inspection do not require ffmpeg. If the optional executable is missing, Ocularium displays a clear install message. This does not require a separate server or GPU.

## Discovery in v0.1

- Enumerates non-loopback IPv4 interfaces and offers one **/24 scan scope** at a time.
- Sends an ONVIF WS-Discovery multicast probe (UDP 3702).
- Sends a UPnP/SSDP M-SEARCH multicast probe (UDP 1900).
- Uses interface-bound mDNS multicast to discover advertised RTSP, ONVIF, and related services (UDP 5353).
- Checks selected TCP service ports across the chosen local /24 using bounded workers.
- Offers **Deep scan unknown** after a normal scan: checks 15 additional service ports only on previously discovered unidentified devices in the selected /24 (maximum 64 hosts, at most 8 concurrent workers). It also sends reverse-IP mDNS PTR queries on the selected local network, which can reveal hostnames from devices that support them. It also sends bounded DNS PTR queries to the selected interface's on-subnet default gateway, which may expose names from router DHCP leases if that router provides local reverse DNS. This is optional, cancellable, and uses no passwords or external services.
- The completed deep scan reports how many hosts and TCP ports it checked, how many additional ports answered, how many distinct hosts returned reverse-mDNS names, and the local-router DNS server, query count, response count, and hostname count. Zero responses are reported explicitly instead of suggesting cameras were found.
- Performs a light RTSP OPTIONS handshake on responding RTSP ports.
- Reads limited unauthenticated HTTP headers and HTML titles from selected open local ports; no credentials, redirects, or cloud access.
- **Automatically enriches self-advertised device descriptions:** after network discovery, fetches a bounded number of SSDP/UPnP XML documents and ONVIF `GetDeviceInformation` SOAP responses. It extracts friendly names, manufacturers, models, device types, and firmware when freely available, and shows their source separately from the MAC vendor.
- Looks up MAC manufacturers using installed local OUI databases; locally administered/randomized addresses are labeled rather than assigned fabricated vendors.
- Offers a **Copy report** button containing scan results and device evidence.
- Saves optional user-authored device labels in `$XDG_DATA_HOME/ocularium/registry.json` (or `~/.local/share/ocularium/registry.json`). Labels use MAC identity where present, falling back to IP addresses; discovery results and camera credentials are **not** persisted.
- **Passive neighbor history (separate opt-in):** Check **Save neighbor observations across restarts** to save MAC-based histories and bounded cache-change events in `$XDG_DATA_HOME/ocularium/neighbor-history.json` (or `~/.local/share/ocularium/neighbor-history.json`). Saving is OFF by default; when enabled, observations are saved about every 60 seconds while watching, on Stop, and on app exit. Turning saving off does not erase previously saved observations. After restart, **Saved passive neighbor history** shows known MACs, IPs, sessions, and recent changes. The store is limited to 512 MAC identities, 12 IPs per identity, and 200 recent events. It never equates cache presence with live camera access and it never stores video or passwords.
- **Observe LAN neighbors (opt-in):** An explicit button samples `/proc/net/arp` every 10 seconds for the selected network interface, tracks first/last seen and changes in the local kernel's neighbor cache, and correlates observed MACs with previously imported DHCP names. It uses no privileged packet capture, probes, or GPU. Observation runs only while Ocularium is open and can be stopped; the bounded event log is in memory and is included in **Copy report**. This is *not* an authoritative connected-devices list, and a device absent from the cache is **not** necessarily offline. Normal network scans and other applications can populate the cache.
- **Router DHCP inventory (opt-in):** The desktop app lets you open the selected interface's on-subnet gateway admin page and paste rows from the TP-Link **DHCP > DHCP Clients List**. It imports tab-separated, whitespace-separated, or CSV tables with client names, MAC addresses, assigned IPs and optional lease times. Ocularium does not authenticate to the router or collect router passwords.
- Import matches observed devices by MAC, falling back to IP only when no device MAC is available. MAC conflicts never silently match by IP. DHCP names appear in the device table, search, details, and copied report; unmatched lease entries remain visible separately instead of being mislabeled as live discoveries.
- The last imported per-network snapshot is persisted to `$XDG_DATA_HOME/ocularium/dhcp.json` (or `~/.local/share/ocularium/dhcp.json`). Importing a new table replaces the prior snapshot for that selected subnet; it does not alter the live scan or sightings history. Router client names are hints, not verified camera models. The app never uploads them externally.
- **Historical sightings** are now recorded in `$XDG_DATA_HOME/ocularium/history.json` (or `~/.local/share/ocularium/history.json`). After each **completed full scan**, the app records first/last observed times, the number of completed scans a device appeared in, observed IP addresses, its last classification and a bounded list of completed scan summaries. Deep scans and cancelled scans do not add sightings. History is retained between application restarts and does not contain credentials or video.
- **Saved device history** in the desktop UI shows devices *not observed in the latest completed full scan*. **Not observed does not mean offline**: sleeping devices, dropped packets, and intermittent discovery can produce false absences. A new IP is linked to an existing record only when the same nonzero MAC is observed; without a MAC, entries are tracked conservatively by subnet + IP. Locally administered/randomized MAC changes can create new historical records.
- History is bounded to 1,024 device identities, 60 recent completed scan summaries, and 12 observed IPs per device. Invalid or newer history data is not silently overwritten; load problems are surfaced as warnings.
- Provides an on-demand **Test RTSP access** action on detected RTSP ports (554/8554, and 8555/10554 if found during deep scanning). You can enter a specific relative RTSP path (default: `/`) and, optionally, your camera's username and password. It sends OPTIONS and DESCRIBE, handles a single RFC-style MD5/MD5-sess Digest challenge and retry, and reports response codes plus SDP codecs when advertised.
- Ocularium **never guesses stream paths or passwords**. Credentials are held in memory only for the one inspection, the password field clears on submission, and neither usernames nor passwords are written into the report or registry. If a device uses a different Digest algorithm, the app reports that limitation rather than falling back to insecure Basic authentication.
- Displays found IPs, detected services, advertised ONVIF addresses/scopes, SSDP headers, and Linux neighbor-table MACs when available.
- Distinguishes confirmed protocol responses from **possible camera** classifications.
- Identifies additional *advertised services*, including AirPlay, Cast, workstation, SFTP, and Matter via mDNS. Identifies HTTP library services from their actual advertised titles (including Caliberate Library) without guessing which physical device runs them. These are evidence of available services, not proof of a particular device's model or exclusion of other functions.
- Supports cancellation, filtering by metadata, and a copyable report. Nothing is uploaded externally.

This is a discovery tool, **not** a vulnerability scanner: no password guessing, RTSP path brute forcing, unauthorized credential extraction, or exploitation. Scan networks you own or are authorized to administer.

### Limitations

- Discovery is limited to the selected IPv4 /24, not the whole LAN or multiple VLANs.
- Device-description requests are restricted to the exact IPv4 host that advertised the document. No DNS resolution, redirects, credentials, or cross-host HTTP requests. Only HTTP is supported for discovery enrichment; HTTPS-only descriptions are skipped rather than weakening TLS.
- Devices may advertise no readable description at all, or may require authentication. Ocularium leaves those **Unidentified** rather than inventing a camera model.
- At most 16 distinct advertised metadata endpoints are probed per scan with short timeouts; requests can add a few seconds after port scanning reaches 100%.
- Wi-Fi client isolation, mesh/router VLANs, multicast filtering, and local firewalls can hide devices.
- Cloud-only cameras may appear as generic TCP devices or not appear at all.
- A reachable TCP port or RTSP handshake does **not** prove a playable video stream.
- Deep scan only checks the already-discovered unidentified hosts. It cannot discover a completely unseen, cloud-only camera on a blocked subnet; even an open unusual port remains a tentative camera hint.
- Reverse-mDNS and router DNS hostnames are optional and often absent. The router may not provide PTR records even when its DHCP lease list has device names; a router may also forward DNS queries upstream depending on its configuration. A hostname is a clue, not proof of the hardware brand or model, and the reverse-mDNS count is the number of responding hosts, not necessarily new camera discoveries.
- MAC addresses are best-effort on Linux; manufacturer lookup requires an existing local vendor database, such as `/usr/share/hwdata/oui.txt`, `/usr/share/ieee-data/oui.txt`, or `/usr/share/nmap/nmap-mac-prefixes`. Missing vendor data is non-fatal. Do not install paid software.
- mDNS can be blocked by multicast filtering or socket conflicts; scan warnings explain failures.
- HTTP titles or RTSP port presence are only identification clues, never proof of accessible video.
- Valid credential discovery, credential persistence, actual RTP playback, recording, snapshots, and MCP are later milestones.
- Even when RTSP returns an SDP description, this is **not** proof that RTP media packets can be received or decoded.
- RTSP inspection tests only the path you enter (`/` by default); 404 does not mean a camera cannot stream elsewhere. Digest authentication is attempted only with both username and password explicitly entered. No redirects, defaults, brute force, or cloud access are attempted.

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

Ocularium runs locally, and v0.1 does not persist credentials. Passwords entered for one RTSP inspection are sent only via the one-time Digest exchange (no Basic fallback) and cleared from the UI. Future streaming and MCP access must require deliberate authorization; credentials must remain unavailable to AI agents.

# Ocularium roadmap

The first target is a **native Rust + egui desktop app** for EndeavourOS/Hyprland. The project should not require knowing the brands or IP addresses of any cameras.

## Milestone 0.1 — LAN discovery

- [x] Rust native app and egui window
- [x] Network adapter selection and local /24 scan target
- [x] ONVIF WS-Discovery multicast
- [x] SSDP M-SEARCH discovery
- [x] Bounded targeted TCP service detection
- [x] RTSP OPTIONS detection (not stream playback)
- [x] Scan progress, cancellation, device details, filtering
- [x] Non-privileged Linux MAC best-effort lookup
- [x] Parser and classification unit tests
- [x] Linux CI checks
- [ ] Validate on the actual household LAN and cameras

## Milestone 0.2 — Identify devices

- [x] Basic mDNS discovery with interface-scoped multicast
- [x] Basic HTTP fingerprinting of selected local ports
- [x] Automatic same-host SSDP XML / ONVIF GetDeviceInformation enrichment, without credentials
- [x] Display advertised manufacturer, model, device type and firmware separately from MAC vendor
- [ ] Authenticate authorized ONVIF responses when the user supplies credentials, without brute forcing
- [ ] Better interface-aware multicast routing
- [ ] Handle duplicate/multihomed device identities
- [x] Best-effort offline OUI lookup using installed hwdata/ieee-data/nmap databases
- [ ] Bundled vendor database or guided optional package installation
- [x] User-triggered bounded deep scan of already-discovered unidentified hosts on 15 additional ports
- [x] Reverse-mDNS PTR hostname queries limited to previously found devices on the selected LAN
- [x] Bounded DNS PTR queries to the selected subnet's on-LAN default gateway, attributed separately from mDNS names
- [x] Deep-scan accounting for checked ports, open ports, and hostname responders, including zero-findings feedback
- [x] Exact Caliberate Library HTTP title recognized as a library service (not falsely labelled Calibre)
- [ ] User-controlled scan scope beyond /24 and configurable ports
- [x] Copyable discovery report for hardware QA
- [x] Persistent user labels keyed by MAC when available (IP fallback), with XDG-local JSON storage
- [x] Persistent local history of completed full scans with first/last observed, sighting counts, historical IPs and per-scope scan summaries
- [x] Opt-in TP-Link DHCP client list import from copied table rows; no router admin password handling
- [x] Correlate imported router leases with live discovery by MAC (IP fallback only if no MAC), and show unmatched DHCP clients separately
- [x] Persist bounded per-network DHCP snapshots locally and expose names with provenance in device details and copied reports
- [ ] Evaluate a documented read-only router integration if the specific firmware exposes a supported interface; no guessed/private authenticated endpoints
- [x] Explicit `not observed on latest completed scan` UX, without claiming an absent device is offline
- [x] Versioned bounded XDG history storage; cancelled and deep scans do not manufacture full-scan sightings
- [x] Evidence-based classification: advertised gateways, media servers, printers, Calibre services, camera candidates and unidentified devices
- [x] Explain why each classification was assigned; separate device descriptions, protocol responses, service advertisements and open-port hints
- [x] Device inventory filters for camera candidates vs unidentified hardware (no manufacturer-based guessing)
- [x] Conservative classification of AirPlay, Cast, workstation, SFTP and Matter advertisements from mDNS
- [x] Opt-in, no-privilege Linux kernel ARP neighbor-cache observation, scoped to selected interface, with 10-second interval and explicit start/stop
- [x] In-session bounded neighbor event log and cache-first/cache-last sightings, correlated with imported DHCP MAC names; no false online/offline claims
- [ ] Persist passive neighbor observations across restarts (opt-in), keeping them distinct from completed active scans
- [ ] Historical evidence tracking and multi-source confidence calibration

## Milestone 0.3 — View

- [ ] Local camera credential management
- [x] Bounded RTSP OPTIONS/DESCRIBE inspection, including user-provided stream path and optional one-shot MD5/MD5-sess Digest authentication
- [x] Hide passwords in egui and clear them after use; never persist or export them
- [x] Replace ambiguous RTSP action label with Test RTSP access and clarify authentication failures
- [ ] ONVIF authenticated stream URI negotiation and playable-stream validation
- [ ] go2rtc integration and live multi-camera viewing
- [ ] Snapshot capture
- [ ] Represent cloud-only camera limitations clearly

## Milestone 0.4 — Agent access

- [ ] Optional systemd-managed local/LAN service
- [ ] MCP list_cameras, get_camera_status, get_snapshot
- [ ] Optional frame sampling, camera access permissions
- [ ] Shared server rather than one server per agent

## Later

Recording, motion detection, event timelines, and optional Frigate/NVR integrations.

## Commitments

- Single executable and no daemon for initial discovery
- Discovery logic separate from egui
- Non-blocking UI
- No cloud requirement for local protocols
- No password guessing or security exploitation
- Test with actual hardware before claiming video support

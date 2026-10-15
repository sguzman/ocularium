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
- [ ] User-controlled scan scope beyond /24, and configurable ports
- [x] Copyable discovery report for hardware QA
- [x] Persistent user labels keyed by MAC when available (IP fallback), with XDG-local JSON storage
- [ ] Persistent historical scan inventory (without stale devices appearing online)
- [x] Evidence-based classification: advertised gateways, media servers, printers, Calibre services, camera candidates and unidentified devices
- [x] Explain why each classification was assigned; separate device descriptions, protocol responses, service advertisements and open-port hints
- [x] Device inventory filters for camera candidates vs unidentified hardware (no manufacturer-based guessing)
- [ ] Historical evidence tracking and multi-source confidence calibration

## Milestone 0.3 — View

- [ ] Local camera credential management
- [x] Bounded RTSP OPTIONS/DESCRIBE inspection, including user-provided stream path and optional one-shot MD5/MD5-sess Digest authentication
- [x] Hide passwords in egui and clear them after use; never persist or export them
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

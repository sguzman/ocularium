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
- [x] User-triggered bounded ONVIF GetCapabilities on advertised same-host HTTP endpoint or one standard port-80 device-service path
- [x] Surface 401/403/404, SOAP faults, and advertised same-host Media capability without assuming usable video access or cloud-only status
- [x] Redacted ONVIF capability diagnostics in GUI and discovery report, with protocol mock tests
- [x] User-reported camera role and app catalog (ANRAN, VicoHome, other, no app), separate from protocol-derived confidence
- [x] LAN-scoped MAC-first persistent camera identities; preserve unseen user-labeled cameras across scans
- [x] Camera inventory, table filters, and safe reports include explicit user provenance without claiming playable video
- [x] Browse all explicitly saved camera records (including not-reviewed, model-only entries) before any network scan
- [x] Reopen and edit saved camera identity, app and metadata offline, without contaminating live discovery or status
- [x] Add ANRAN panel shortcut to the **sole** saved, unassigned-app record's offline identity editor, with accurate zero-matching explanation; no automatic camera role/app assignment and no network activity
- [x] Prefer available network scope with saved camera profiles on app startup; preserve missing-device warnings
- [x] Regression-test saved model-only profile round trip and identity reconstruction without network evidence
- [x] Optional user-entered private camera hardware metadata (model, firmware, platform, serial/device ID), backward-compatible registry
- [x] Owner-only Linux registry file writes, masked device ID UI and serial-redacted copied reports
- [x] Show session-specific, protocol-grounded local video evidence separately from app/model identity
- [ ] Validate ANRAN and VicoHome official/authorized integration opportunities before collecting any app credentials
- [ ] Correlate user-labeled household cameras with app-side device identifiers if supported, without assuming cloud API availability
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
- [x] Opt-in persistent MAC-based passive observations with historical IPs, observation-session counts, and bounded cache events
- [x] Periodic and on-stop/exit writes; session checkpoints prevent double-counting repeated saves, and active full-scan history remains separate
- [ ] Provide in-app deletion of saved passive history and structured export options
- [ ] Historical evidence tracking and multi-source confidence calibration

## Milestone 0.3 — View

- [ ] Local camera credential management
- [x] Bounded RTSP OPTIONS/DESCRIBE inspection, including user-provided stream path and optional one-shot MD5/MD5-sess Digest authentication
- [x] Hide passwords in egui and clear them after use; never persist or export them
- [x] Replace ambiguous RTSP action label with Test RTSP access and clarify authentication failures
- [x] Report initial and authenticated DESCRIBE status separately, whether a Digest retry was sent, and redacted algorithm/qop/stale challenge metadata
- [x] Reuse challenge TCP connection for one authenticated DESCRIBE retry; mock RTSP server tests validate handshake and rejection cases
- [x] Validate Digest response hashes against independent MD5/no-qop and RFC 2617 qop known-answer vectors
- [x] Distinguish socket-write failure from an authenticated DESCRIBE successfully sent to the device
- [x] Mask RTSP username by default with optional reveal for screenshot privacy
- [x] Copy safe RTSP diagnostic with no password, username, stream path, Digest realm, nonce or Authorization header
- [ ] Verify the YGtek RTSP Server 2.0 challenge/response on household hardware with supplied credentials and non-guesswork stream path
- [ ] ONVIF authenticated stream URI negotiation and playable-stream validation
- [ ] go2rtc integration and live multi-camera viewing
- [x] Optional one-frame CPU RTSP capture with local ffmpeg for unauthenticated, explicitly supplied streams, bounded to 12 seconds and 640×360 in-memory pixels
- [ ] Secure authenticated snapshot decoding without exposing credentials in subprocess arguments
- [ ] Continuous live preview and multi-camera viewing
- [x] Experimental source-neutral local HTTP MPEG-TS frame intake (loopback/LAN only, no secrets or external HTTP, bytes via stdin to CPU ffmpeg)
- [x] Saved-camera UI to attach a transient local stream URL and display one decoded frame without persisting endpoint or credentials
- [x] Document ANRAN/Meari and VicoHome integration evidence, with explicit unverified-device boundary
- [x] Implement bounded, offline native Meari VVP command encoding / plaintext media framing / replay gating with synthetic tests; no network or credentials
- [x] Add offline VVP plaintext H.264/HEVC Annex-B elementary stream adapter and CPU ffmpeg single-frame decode (synthetic tests, no P2P/crypto/network)
- [x] Add explicit offline VVP fixed-key 3DES-ECB legacy video-frame decryption, strict one-frame validation, independent ciphertext test vectors and decoder handoff (NOT optional camera E2EE or peer authentication)
- [ ] Investigate optional per-device video-password/E2EE behavior only if documented and supported by verified hardware; do not guess keys or enable automatic retries
- [x] Add separate offline PPCS reliable-channel → 32-byte media-frame → validated H.264/HEVC access-unit → CPU decoder handoff; gated on independently verified session input, no network/decryption/automatic playback
- [x] Add offline PPCS eight-channel ordered receive buffering and 32-byte media-frame reassembly (no network, no crypto, synthetic loss/reorder/wrap tests)
- [x] Add offline legacy PPCS packet envelope and reversible substitution cipher with independent wire vectors and integration tests; do not mistake packet obfuscation for peer authentication
- [x] Decode bounded PPCS factory-9 device identity and init relay/cipher material, validate 16-byte IPv4 sockaddr, and enforce root/candidate match in synthetic rendezvous preflight
- [x] Add an explicit, mock-I/O PPCS rendezvous probe controller with authoritative record selection, finite per-root requests, offer/response filtering, five-second deadline, budgets and teardown (no sockets or background service)
- [x] Implement uninvoked, explicit IPv4 UDP socket adapter with short read/write timeouts, bounded datagrams, local-bound address matching and loopback-only integration tests
- [ ] Enable a verified, opt-in PPCS UDP session from the native GUI only after confirming the household camera's PPCS backend and defining peer/session authentication; no automatic access
- [ ] Verify device-specific P2P transport, authenticated packet decryption, peer rendezvous and media codec decryption before connecting real camera streams
- [x] Require authoritative device-list transport field before selecting PPCS versus modern signaling (do not infer from platform b81)
- [x] Offline bounded parsing of successful Meari camera device-list responses (default + shared homes), session-only transport/key data, redacted summaries, MAC-only correlation
- [x] Mock-tested native ANRAN redirect → one-shot login → signed default device-list handshake with independent legacy crypto vectors
- [x] Diagnose post-login list failure by fixed, redacted default/home/shared-home endpoint outcome categories; preserve no-response-body, no-retry, no-credential-persistence boundary
- [ ] Investigate actual US-account device-list rejection/transport incompatibility using diagnostics from one newly consented QA attempt only when warranted; do not interpret current failure as bad credentials or incompatible hardware
- [x] Bounded TLS-verifying transport restricted to vendor HTTPS domains, with proxy/redirect disabled, no GUI connection or automatic requests
- [x] Add a consent-gated, one-shot ANRAN account panel with masked transient fields and count-only results
- [x] Test consent-to-worker handoff (no connection before consent; credential fields cleared once transferred); best-effort buffer zeroization
- [x] Triangulate ANRAN app identity against its App Store Meari/84 link and the community profile; separate app-level evidence from individual camera support
- [x] Block ANRAN login until user explicitly confirms their camera is paired with the ANRAN mobile app, not ARCCTV/CloudEdge/EseeCloud; reset credentials/consent when app changes
- [x] Offline and worker-integrated, selected-LAN ANRAN camera MAC correlation: report redacted one-to-one matches, ambiguity and missing identifiers; no cross-app/scope IP or model linking
- [x] Redacted ANRAN PPCS metadata prerequisite preflight from temporary authorized owner/shared catalog: explicit transport only, parseable identity/init, host-key presence, missing/malformed counts, no extra requests or credential retention
- [x] Count PPCS transport and complete/incomplete PPCS metadata for **uniquely MAC-matched selected-LAN saved cameras**; duplicate/absent MAC never matches, count-only UI, no extra HTTP, UDP or persistence
- [ ] Validate the household camera's authoritative transport declaration via one deliberately consented account lookup before considering live PPCS probing
- [x] Add bounded, one-shot shared-home discovery (up to 8 unique homes) with signed GET requests, owner/shared merging, redacted completeness, and no retry
- [x] Optional, default-off one-shot Meari `pf/init` inspection: signed GET, response shape validation, redacted feature-presence flags, transient/malformed status, no retries or outbound service calls
- [ ] Platform credential decryption / P2P platform authorization only after compatibility verification and separate review
- [ ] Build an opt-in, secure ANRAN account client that can verify an authenticated device list before trying streaming; keep credentials/tokens out of disk and logs
- [ ] Verify ANRAN's exact account backend and device protocol prior to implementing any app authentication
- [ ] Add real ANRAN video adapter without mandatory external server; do not infer compatibility from app branding alone
- [ ] Support VicoHome event media when owner-authorized export/integration is available (not live RTSP)
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

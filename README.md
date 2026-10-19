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

## Household camera identity catalog

Ocularium keeps **network evidence** separate from **user-provided camera identification**. Select any discovered device and use **User camera identity and app** to mark it *Possible camera*, *Camera (user-confirmed)*, *Not a camera*, or *Not reviewed*. Assign the app only when known: **ANRAN**, **VicoHome**, another app, no app, or not identified. These annotations are never inferred from OUI/chipset vendors or open ports.

The **Household camera inventory** section includes user-marked possible/confirmed cameras even when they were **not observed in the current scan**. Device-table filters include user-marked cameras while preserving the separate protocol evidence and explaining when a device was user-identified. The catalog is persisted locally in the existing `$XDG_DATA_HOME/ocularium/registry.json` (or `~/.local/share/ocularium/registry.json`), with backward-compatible existing aliases. Identities are scoped to the selected LAN and keyed by MAC when available, falling back to IP; IP-only records are explicitly cautioned and are not silently transferred to newly identified MACs.

No credentials, video frames, app tokens, or cloud accounts are saved. User confirmation means someone identified the camera, **not** that RTSP/ONVIF works, that the device is connected, or that Ocularium can play video.

## Editing saved camera records without scanning

**Saved camera records** appears above the live discovery table and is expanded by default on launch. It shows **every explicitly saved camera profile**, including entries left at **Not reviewed** that contain only a saved model such as CQ1F. Click **Edit saved** to update the label, role, managing app, model, firmware, platform, or private serial without running a LAN scan. Only the saved MAC/IP identity is reconstructed for editing; it is **never inserted into the active discovery results**, and saved-record editing does not trigger RTSP, ONVIF, or other network probes. The status clearly distinguishes historical records from devices observed in a current scan.

When possible, Ocularium initially selects an available LAN that already has saved camera records instead of an unrelated bridge interface. This changes only the selected dropdown; it does not scan. The saved editor uses the existing backwards-compatible local registry, and serial numbers remain masked and omitted from copied reports. Existing saved roles, labels, and metadata remain unchanged during the upgrade.

## Private camera hardware metadata and access evidence

The camera identity editor now has an optional **Camera hardware details** section for model, firmware, device platform/MCU, and a user-entered serial/device ID. These fields are saved **only when you click Save camera identity**; they are not prefilled with private household identifiers in this public repository. Serial fields are masked by default, excluded from **Copy report**, and replaced there with a yes/no presence flag. The XDG-local `registry.json` is written using owner-only permissions (`0600`) on Linux. No app passwords, cloud login tokens, video, or credentials are stored.

The household inventory distinguishes **user-provided identity** from **live access evidence**. It can display a protocol-level RTSP response, rejected RTSP access, advertised ONVIF Media, received SDP, or a successfully decoded single frame **during the current application session**. A saved model, app selection, or chipset vendor is never interpreted as proof that live viewing works. Without a new scan/test the app reports **not checked in this session**, not "offline" or "cloud-only".

**Experimental ANRAN account discovery (opt-in):** The application now offers a manually opened panel for one explicit CloudPlus/Meari login, default device-list request, home-list request and up to eight additional shared-home device-list requests. This unofficial integration is not yet verified against the household camera and may sign out an active mobile session. Credentials are masked, removed from the form when submitted, and never written to disk or reports. Only aggregate device counts, selected-LAN MAC-correlation counts, coverage/completeness counts, or fixed error categories reach the GUI. A rejected or malformed shared-home response is reported as partial rather than silently equated with no cameras. No automatic login, retries, camera stream, or VicoHome account integration is implemented. An additional default-off checkbox can request exactly one IoT platform-configuration inspection during consented discovery; it reports only the presence of service configuration sections, never their URLs or access keys. It performs no OpenAPI, MQTT or P2P connections. Do not enter app credentials into RTSP fields. **App/backend preflight:** First choose the actual app where the camera appears. The panel begins with **Unknown / not checked** and conceals login inputs until **ANRAN app** is selected and the user explicitly confirms that camera is paired there. ARCCTV, CloudEdge, EseeCloud, and other apps cannot use this ANRAN-only protocol. Changing the selection clears consent and credentials. App identity is still not proof of device-level P2P compatibility. If a one-shot login succeeds, the app may report **unique MAC matches versus ambiguous/missing matches** against saved records labeled ANRAN on the selected LAN. The comparison is local only; no MACs are sent to the account service or persisted as new evidence. A zero-match result does not prove that the camera or account is incompatible. **Human GUI QA previously passed for the initial account panel; no new credential test is requested.** Do not submit a real account without reviewing potential mobile-session effects.

## ONVIF capability investigation

Select a discovered device and click **Inspect advertised ONVIF** if it supplied a WS-Discovery ONVIF URL. Ocularium checks only one same-host, plain-HTTP advertised endpoint; it never follows off-host URLs, redirects, or handles credentials. If the device did not advertise an ONVIF service, the UI instead offers **Check standard ONVIF service**, which sends one unauthenticated SOAP GetCapabilities request to the conventional `http://DEVICE_IP/onvif/device_service` endpoint on port 80. It does not sweep ports or attempt password guessing.

Results distinguish no HTTP response, 401/403 authorization barriers, 404 missing endpoint, SOAP faults, and recognized ONVIF capability categories. If an ONVIF Media service URL is advertised, its hostname must match the selected device before the UI marks it as same-host. **Copy safe ONVIF diagnostic** and the discovery report contain status/capability evidence without raw service URLs or credentials. ONVIF advertising is not proof a stream is playable, and absence of an ONVIF reply is not proof of a cloud-only camera. This feature does not request stream URIs or decode video.

## Direct, offline saved-camera review from ANRAN

After the first account QA, a saved model-only CQ1F record existed but was labeled neither a camera nor an ANRAN app camera; consequently the ANRAN panel displayed zero saved records for MAC comparison. The panel now explains that **zero marked ANRAN records does not mean the camera is offline or that login failed**. When exactly one saved, non-excluded profile still has its managing app unassigned, it offers **Review saved camera identity (offline)**, opening that saved profile's existing Camera role / Managed by editor. The saved inventory also labels unassigned records more clearly. The user must explicitly choose and save the role/app; nothing is inferred from the CQ1F model, IP or an app login, and nothing is automatically written. With multiple candidates, the shortcut disappears to prevent editing the wrong device. This does not log in, scan, contact the camera or expose credentials.

## Validated ANRAN catalog response shape (not silent empty results)

A vendor response with `resultCode=1001` but no recognized device-list structure must not be counted as a verified, empty catalog. The native catalog parser now differentiates a genuinely empty `result: {}` or an explicitly empty known `ipc`/`deviceList` collection from an unknown nonempty response shape, a missing `result`, or an unexpected type. Such mismatches produce the existing fixed **unexpected response** diagnostic and never claim camera incompatibility. This change needs no new requests, credentials, UDP access or user QA; synthetic tests cover known nested collections and foreign API shapes.

## Canonical ANRAN region after redirect (no additional login)

The pinned community client copies an optional `result.countryCode` from the HTTPS redirect response before constructing signed login and device/home-list requests. Ocularium previously kept the form's country unchanged, even if the trusted API redirect returned a canonical registration country. It now accepts **only a two-letter uppercase country code** from the already-allowlisted redirect response and applies it to the remaining requests; the phone dialing code remains explicitly user-supplied. Invalid redirect-country values fail before login. New synthetic tests verify the full request sequence and stop-on-invalid behavior with no real account access, additional requests or retries. This correction does not establish camera compatibility.

## Reference-compatible ANRAN nonces (offline)

The community ANRAN client uses two separate nonces on redirect: an eight-digit decimal query `nonce` and a six-digit decimal `X-Ca-Nonce` header. Subsequent signed requests also use six-digit decimal header nonces. Ocularium previously reused one 12-character hexadecimal nonce for both. It now derives separate numeric nonces from OS-backed randomness, validates both formats before request construction, and tests these fields offline. No additional network request, retry, account login or camera access was added. Camera-list compatibility remains unverified.

## Native ANRAN HTTP compatibility and bounded failure categories

The ANRAN HTTPS client now sends the exact **mobile User-Agent string in the pinned community implementation**, instead of the Rust HTTP library's default. This aligns a concrete request header without changing the app's declared ANRAN wire profile or authorizing new network traffic. It also classifies HTTP failures by a **fixed, redacted category**: 401/403 access denied; 404/405 missing endpoint; 408/429 throttling or timeout; 5xx server error; and other unexpected HTTP statuses. Network, TLS and transport timeouts stay a separate category. These classifications reach the GUI only through the already-consented, single-shot lookup, and are preserved when the home listing succeeds but the default camera-list request fails. Neither full HTTP status codes, URLs, account details, response bodies nor tokens are retained in diagnostics. Tests use synthetic failures across a full redirect/login/default/home/shared sequence, without requests to ANRAN. This is **not** proof of live camera compatibility and is **not** a reason to repeat a disruptive account login yet.

## Observed phone-app session eviction and faithful QA regression

Repeated, explicitly consented ANRAN login tests have signed the account's mobile app out. This is strong evidence that Ocularium establishes a vendor login session, **not** proof of camera-list compatibility, a verified peer or video access. The account panel now warns that logout has actually happened in QA. No account login is needed to validate this offline change; minimize repeat attempts because each may disrupt the app's active session.

The one-shot account regression now models the actual partial result: default device-list failure, an accepted home list, one successfully processed shared-home list, and zero camera records. Tests separately cover default request network failure and rejection while preserving the redacted diagnostic and without retries.

## Partial-success ANRAN diagnostics (October 19 QA follow-up)

Owner-authorized QA of a US-registered ANRAN account showed a successful redirect/login and home listing, with one shared-home list call succeeding, **but no camera records returned** because the default-device list remained unavailable. This is a **partial inventory**, not proof the account contains no cameras or that the saved CQ1F is incompatible. The worker previously retained a detailed failure category for the default list only on total lookup failure; a successful home request would discard that category. The UI now also shows redacted per-endpoint outcomes on *partial successes* (transport failure, temporary vendor unavailability, rejected or unexpected reply), alongside the existing coverage counts. Synthetic mock tests verify that no additional HTTP calls, retry, persistent credentials, peer contact or model-based matching occur. No new login is required for this fix; the previous attempt's exact default-list cause cannot be recovered retroactively.

## ANRAN post-login signing compatibility (offline regression)

The pinned community API sends `localTime` during **redirect and login**, but omits it from the **signed authenticated device-list, home-list, shared-home and optional platform requests**. Ocularium previously included the extra field in those signed requests, changing their HMAC and potentially causing rejection after a successful login. The builders now reproduce the documented field sets and verify independently generated US-region HMAC-SHA1 signatures, preserving the existing no-retry consent gate and credential handling. Successful home responses with an omitted `homes` field are also interpreted as an empty list, as in the reference; malformed types remain rejected. **These are offline compatibility corrections, not proof the household camera is compatible.** No account or camera was contacted to validate the fix.

## Post-login camera-list failure diagnostics (no automatic retry)

Following hardware QA on a US-registered, owner-authorized ANRAN account, login was apparently accepted but Ocularium displayed only "No verified device list." The account client now preserves **fixed outcome categories** for the default-device and home-list endpoints, distinguishing network/HTTP failure, temporary vendor unavailability, explicit list rejection and malformed/unexpected responses. It also counts attempted shared-home requests and their transport/rejection/format failures. If all catalog retrieval routes fail, the GUI now reports these **redacted stage diagnostics** rather than implying that the password or camera is invalid. No response bodies, numeric account IDs, tokens, home IDs, domains, or raw vendor error text enter the UI. No additional requests or retries have been added. The user should not repeat a real login solely for this change; further account QA requires renewed consent and should be justified by a concrete diagnostic need.

## Saved-camera PPCS matching (redacted, no extra traffic)

The existing consented ANRAN account lookup now also reports PPCS compatibility *for uniquely matched saved cameras in the selected LAN scope*. It compares normalized MAC addresses using a **strict one-to-one rule**: duplicate, missing, or invalid MACs on either side never match, and model names, camera IPs, app branding, and serials are not used as fallbacks. The GUI shows only counts of uniquely matched PPCS, signaling and unknown-transport cameras; for matched PPCS records, it distinguishes syntactically complete from incomplete device identity/init/host-key fields. This complements the account-wide PPCS counts and existing MAC-correlation summary. A matched MAC does **not** cryptographically verify hardware or authorize video; it is simply stronger evidence for choosing which camera to investigate. No saved record is mutated, no secrets cross the worker/UI boundary, and no extra network request or automatic P2P probing occurs.

## ANRAN PPCS account metadata preflight (redacted, no extra traffic)

After the existing **explicitly consented** ANRAN account lookup, the GUI now reports aggregate PPCS protocol prerequisites from the transient authenticated default/shared-home catalog. It counts only cameras whose authoritative `deviceP2P` field explicitly declares `ppcs`, then independently distinguishes missing/malformed factory `deviceUUID`, malformed/missing `p2pInitApp` or `p2pInit` relay/init strings, and missing/invalid `hostKey` material. A count of records with all fields syntactically valid is **not a camera compatibility or authentication result**. Model/platform names, IPs, and app branding cannot create a PPCS declaration. This check opens no new network connection, uses no device credentials outside the existing temporary catalog, saves nothing, and shows only fixed counts rather than IDs, host keys, hosts, or init strings. If account-list coverage is partial, these are only the records actually returned.

## Explicit native UDP transport primitive (not enabled in the GUI)

`src/meari_ppcs_udp.rs` implements a synchronous, single-socket IPv4 UDP adapter for the existing bounded PPCS probe controller. The socket is bound **only by an explicit call** to a selected local interface; it has a 75 ms receive timeout and bounded datagrams (16 KiB + 4-byte envelope). The controller checks that the socket's actual local address matches its advertised rendezvous address, then exits on its existing deadline, packet budget, or unverified candidate response. One-shot results expose redacted counts, not identifiers, peer addresses or keys. The socket closes automatically on drop. Tests use UDP loopback only, checking real send/receive, cipher compatibility, oversized datagrams, timeouts, and refusal to transmit on an incorrect binding. **No GUI button, startup hook, background server, DNS resolution, household network access, actual camera login, or automatic probing is introduced.** PPCS packets and device-ID replies still lack cryptographic peer authentication and cannot authorize media access.

## Offline bounded PPCS probe controller (not a camera session)

`src/meari_ppcs_probe.rs` connects the existing device-list transport selection, PPCS initialization/identity parser, packet codec, and rendezvous preflight behind an **explicit one-shot controller**. Only a session-only camera record marked `Ppcs` can provision it. No network activity occurs during construction. A caller must supply resolved root endpoints and an I/O implementation; there is **no UDP socket implementation, GUI action, DNS lookup, automatic retry, or background task**. The controller emits one hello and one rendezvous request per root, then accepts only root-offered peer candidates with the expected DID. It caps the round at five seconds, eight roots, four offers, 48 outgoing datagrams, and 64 incoming datagrams; a timeout, send failure, or explicit close ends the probe. Outcomes are deliberately labeled **unverified candidate**, because the legacy substitution cipher carries no authentication or integrity guarantee. Synthetic tests cover authorization checks, initialization, source filtering, response ordering, budgets, timeouts and teardown.

## Offline PPCS rendezvous preflight (no camera connection)

`src/meari_ppcs_discovery.rs` now decodes factory-9 PPCS device UUIDs and source-provided initialization strings into bounded device identity, relay-host names, and a transient derived packet cipher. It also validates PPCS IPv4 socket-address packets and checks root offers and candidate responses against explicitly provided root IPs, exact device bytes, and a three-port punch radius. The included test runs a synthetic offer/response through the existing packet codec. This logic **never resolves DNS, opens a UDP socket, contacts the camera or verifies a peer cryptographically**. Future networking must separately authenticate the account/device and bind the intended peer before treating any response as trustworthy.

## Offline PPCS packet codec (not an authenticated connection)

`src/meari_ppcs_wire.rs` now implements the legacy PPCS 0xF1/type/big-endian-length packet envelope and the reference's reversible packet substitution cipher. It bounds datagrams, clears transient plaintext and derived state, and checks fixed wire vectors against the independently implemented reference. It can feed its decoded inner channel packets into the existing offline receiver. **This cipher is obfuscation, not authentication or integrity protection.** No real keys, peers, UDP sockets, network requests, or cameras are involved; future transport code must verify the authorized device/session and sender independently before interpreting these packets.

## Offline legacy PPCS receive-side reassembly (not a camera connection)

`src/meari_ppcs.rs` now models eight PPCS reliable channels and their legacy **32-byte media envelopes**, separate from VVP media framing. It bounds reorder buffering, suppresses duplicates, handles 16-bit sequence rollover, and reconstructs media frames from fragmented, already authenticated/decrypted reliable-channel bytes. Synthetic tests exercise fragmentation, reorder, invalid headers and reset behavior. It cannot contact a camera, authenticate/decrypt PPCS packets, choose the correct media channel, or stream video.

## Offline PPCS media → CPU decoder handoff (not a live camera stream)

`src/meari_ppcs_video.rs` connects the existing eight-channel PPCS reliable receiver, PPCS **32-byte media** reassembler, Annex-B H.264/HEVC validation, and one-frame CPU decoder. The media channel must be selected by a **separately verified and authorized session**; there is no path from an unverified PPCS rendezvous candidate to this adapter. It suppresses duplicate/out-of-order packets, reorders fragmented media, skips audio, caches codec parameter sets for keyframe recovery, rejects unrecognized/encrypted payloads, and waits for a new keyframe after video-sequence gaps. The adapter returns inert ACK metadata but **never transmits an ACK** or launches FFmpeg itself. Synthetic tests cover H.264/HEVC, fragmentation, channel isolation, corruption/reset, recovery and optional CPU FFmpeg frame decoding. It neither sends network packets nor decrypts camera media, and no household video stream is enabled.

## Offline legacy VVP stream decryption (not E2EE or camera access)

`src/meari_stream_crypto.rs` implements the **legacy video-frame 3DES-ECB transformation** documented by the pinned Meari community reference: the vendor's fixed 15-byte key padded to 24 bytes, at most 128 encrypted bytes starting at the I-frame/P-frame offsets, and complete eight-byte blocks only. Each call requires **exactly one fully reassembled VVP video frame** and an explicit per-session choice of plaintext versus legacy encrypted mode. It strictly rejects wrong lengths, invalid frame markers, unexpected concatenation and unrecognized Annex-B payloads; it never guesses ciphertext based on an IP address or camera model. Recovered video passes through the existing H.264/HEVC keyframe gate and CPU decoder path. Independent TripleDES known-answer vectors, truncation/corruption and state-reset tests run in CI. This **does not decrypt optional end-to-end camera video passwords**, authenticate a peer, contact the network, or enable live camera playback.

## Offline VVP video-to-CPU decoder (not a camera connection)

`src/meari_video.rs` is a standalone Rust adapter for **already authorized, reassembled, plaintext** Meari VVP video packets. It validates Annex-B H.264/HEVC parameter sets, gates recovery on actual codec keyframes, rejects duplicate/out-of-order video and gaps until a new keyframe, bounds input, and feeds only codec bytes over stdin to a local CPU `ffmpeg` decoder for one transient 640 × 360 RGB frame. It never starts a network connection, chooses a camera, stores video, logs device identifiers, decrypts unknown payloads, or sends a URL to ffmpeg. The synthetic FFmpeg round-trip is automated when the optional local H.264 encoder exists. The adapter is **offline groundwork only**; no household live video, P2P authorization, or live transport reassembly is implemented. The separate legacy 3DES module handles only its documented, fixed-key VVP transform; optional per-device E2EE remains unsupported.

## Experimental generic local MPEG-TS source

In the **Saved camera records** editor, expand **Experimental local stream frame (MPEG-TS)** and supply an *already authorized, existing* `http://private-IPv4:port/path` endpoint from your own LAN or loopback. **Capture frame from local stream** fetches its MPEG-TS bytes locally and attempts to display exactly one CPU-decoded frame with ffmpeg, without persistent recording or credentials. The URL is not saved, shown in reports, or passed to ffmpeg; the decoder receives only video data over stdin. The HTTP client blocks external destinations, URL credentials and tokens, DNS, redirects, cookies, and proxies; inputs and byte counts are bounded. This does **not** connect to ANRAN/VicoHome accounts or create a local stream server.

VicoHome officially does not support third-party RTSP/ONVIF live feeds, while experimental community ANRAN/Meari integrations may work for some products. Compatibility with the household cameras has **not** been verified. For sources and adapter milestones, see [camera ecosystem integration research](docs/camera-integrations.md). ANRAN login must only be attempted after explicit informed consent in its experimental panel; do not enter app passwords into RTSP fields.

## Experimental single-frame RTSP capture

Select an RTSP-capable discovered device and enter its **exact stream path** (no endpoint guessing). Click **Capture one frame :PORT**. If the local `ffmpeg` executable is installed, Ocularium runs it in a bounded worker to attempt CPU decoding of a single 640 × 360 RGB frame, shown as an in-memory egui texture. Capture is manually triggered, runs at most 12 seconds, and never records, uploads, saves, or includes image pixels in reports.

**Authentication regression checks:** The RTSP Digest calculation now has fixed known-answer tests covering the camera's reported **MD5 / no-qop** variant, the published RFC 2617 MD5/qop example, and MD5-sess without qop. The inspector reports an authenticated retry as "sent" only after the socket write succeeds. RTSP usernames are hidden in the GUI by default (with an explicit Show toggle) to avoid accidental disclosure in screenshots.

**RTSP authentication diagnostics:** **Test RTSP access** now distinguishes the initial unauthenticated `DESCRIBE` status, whether a Digest-authenticated retry was actually attempted, and the retry response code. The retry reuses the same TCP connection as the challenge with a fresh `CSeq`. The GUI shows safe challenge metadata (algorithm, qop, stale flag) without displaying the Digest realm or nonce. **Copy safe RTSP diagnostic** exports those findings without the username, password, Authorization header, or stream path. A final 401 is *not* proof the password is wrong: device RTSP permissions, path, and implementation compatibility are also possible causes. A test that never sent authentication is explicitly marked as such. At most one authenticated attempt is sent, and nothing is saved to disk.

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

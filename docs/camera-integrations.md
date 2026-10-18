# Camera ecosystem integration research (2026-10-17)

This is technical planning, **not** a claim of working Ocularium app-account access or support for every camera.

## ANRAN

- Ocularium has a user-identified ANRAN camera; manufacturer branding and a mobile app name do **not** establish its protocol or cloud backend.
- ANRAN's official support website lists distinct **ANRAN** and **ARCCTV** phone apps, as well as EseeCloud desktop software. Its separate product support page divides ANRAN-app and ARCCTV-app equipment. An ANRAN-branded camera therefore does not identify the login backend by itself: https://anran-cctv.com/pages/support-app-download and https://anran-cctv.com/pages/support
- **Independent ANRAN-app/Meari evidence:** The App Store listing for the Shenzhen Anran Security Technology iPhone app (id `1611278380`) includes a subscription-policy URL on `meari-us.s3.us-west-1.amazonaws.com` under `/html/audit/84/`: https://apps.apple.com/mx/app/anran/id1611278380 . Separately, the MIT-licensed community client defines an **ANRAN-only** profile with `sourceApp=84`, `partnerId=84`, `phoneType=i` (snapshot c363366e5a712d6a0fee2be811eee23e15ee627a): https://github.com/raulrojas22/Ha-CloudPlus-Meari-ANRAN/blob/c363366e5a712d6a0fee2be811eee23e15ee627a/custom_components/cloudplus/api.py#L71-L103 . This triangulates the *app identity*, **not** any specific camera's account membership or P2P transport.
- CloudEdge and ARCCTV are **not** equivalent to the `sourceApp=84` client. The community client uses a separate CloudEdge profile (`sourceApp=8`) and the ANRAN vendor gives ARCCTV its own mobile/NVR setup path. Do not send ARCCTV/CloudEdge/EseeCloud credentials to the ANRAN-specific handshake: https://anran-cctv.com/pages/how-to-view-wireless-camera-system-on-phone-app
- **Experimental community lead:** https://github.com/raulrojas22/Ha-CloudPlus-Meari-ANRAN includes an ANRAN app profile and reverse-engineered CloudPlus/Meari P2P streaming. It is unofficial and not verified compatible with this household device. The repository's documentation notes cloud login, possible single-session conflicts, and optional video encryption codes. It is *not* an official ANRAN API.
- **Boundary for future adapter:** This is an experimental community protocol, not an independently verified match for the household ANRAN camera. The consent-gated UI exists, but live account QA should follow verification that the camera uses this backend; login could invalidate the active mobile session. Do not import external code without reviewing its license and security.

## VicoHome (CQ1F)

- Official documentation explicitly says no NVR, RTSP or ONVIF integration: https://support.vicohome.io/hc/en-us/articles/49415792736281-How-to-Integrate-Cameras-with-NVR-Systems
- **Experimental community lead:** https://github.com/TomTje/vicohome-ha uses undocumented cloud endpoints and advertises event images/clips, **not live streaming**. Compatibility and continued access are not established, and its documentation flags single-session token concerns.
- **Boundary for future adapter:** An owner-exported clip or an approved event-image integration may be useful, but do not describe an event thumbnail or an archived clip as a live camera frame. No proprietary-login code is in Ocularium.

## Current implemented local video intake

Ocularium can now take **one** frame from an explicitly supplied local HTTP MPEG-TS source using a CPU ffmpeg decoder. This is a generic handoff for a future authorized local bridge, not a bridge implementation or cloud API client.

Security properties:
- Accepts only numeric loopback or private IPv4 HTTP URLs with explicit port and path, no URL credentials, query, or fragment.
- Uses an internal HTTP reader with proxies and redirects disabled, no DNS and no cookies.
- Streams bounded bytes to ffmpeg via stdin; the decoder never receives endpoint URL or cloud credentials.
- Times out decoding, caps video bytes, keeps the result as a transient egui texture.
- Endpoint is held only in application memory, never persisted to registry or included in copied reports.
- The optional source requires an external compatible endpoint; ordinary Ocularium discovery remains a standalone native app.

## Native Rust Meari VVP protocol groundwork (offline)

`src/meari_vvp.rs` implements bounded plaintext VVP media-frame parsing, sequence/keyframe replay gating, the 60-byte authenticated VVP command **encoder**, and explicit P2P transport selection from the authoritative logged-in device record's `deviceP2P` field. All code is pure and in-process: it sends **no** packets, contacts **no** cloud or camera, imports **no** Python runtime, and stores **no** credentials. Tests use synthetic device records and frames with fictitious authentication keys.

Protocol layout reviewed against the MIT-licensed community source:
- `custom_components/cloudplus/p2p_streamer/protocol.py`: command byte order, magic, MD5 material and command IDs
- `custom_components/cloudplus/p2p_streamer/codec.py`: per-frame payload offsets, timestamp and sequence
- `custom_components/cloudplus/p2p_streamer/engine.py`: transport selection from `deviceP2P`

**Offline codec handoff (no camera account or transport):** `src/meari_video.rs` consumes only *complete, reassembled, already decrypted* VVP video frames and extracts bounded H.264/HEVC Annex-B access units. It requires SPS/PPS for H.264 or VPS/SPS/PPS for HEVC and matching keyframe NALs, preserves sequence continuity, and waits for another keyframe after gaps. Cached parameter sets can be prepended to a recovery frame. It refuses unrecognized/encrypted-looking bytes rather than trying to decrypt or guess. The standalone CPU decoder accepts these elementary bytes on ffmpeg stdin, without URLs, a server, or GPU access; its output is a single bounded in-memory RGB frame. The synthetic tests do not establish actual camera compatibility. **Neither account authentication nor P2P delivery is connected to this offline module yet.**

The user-observed ANRAN camera's **platform b81 is not its P2P transport field** and therefore cannot establish Meari compatibility or whether it uses modern signaling versus legacy PPCS. A matching app name alone does not validate the account backend. Live video still requires account-authorized device discovery, verified transport/signaling and key management, media decryption where enabled, and delivery of complete codec frames to the native decoder.

The module intentionally rejects zero-length or excessively large media payloads and never attempts to decrypt data guessed to be plaintext. Payloads only become usable after the future authorized transport layer has reassembled them.

## Authenticated Meari device-list normalization (native Rust, offline)

The new `src/meari_devices.rs` implements an **in-memory, bounded parser** for the camera-list response a future authenticated Meari-family account client may receive. It covers account-owned and shared-home device groups, deduplicates repeated `deviceID` records without cross-merging different devices, and classifies `ipc`, `snap`, and doorbell categories. A successful response marker is required; the `1023` transient code is recognized separately. **A marker in JSON does not authenticate a response by itself**: the future client is responsible for making the authenticated HTTPS request and verifying the server.

It retains session-only fields needed by a future media adapter, including `deviceP2P`, `hostKey`, `p2pInit`, `deviceUUID`, and `snNum`, but these types have no Debug/Serialize capability and are **not saved to the existing registry**. The only public diagnostic is a count of cameras/categories/transport declarations; secrets, addresses, MACs, and device IDs are never included. Strict JSON-size, recursion-depth, and record-count limits prevent unbounded input from an upstream API. A future account integration must define the credential/token lifecycle and avoid diagnostic exposure before this parser is wired to real logins.

Local inventory correlation is **MAC-only**, if the backend actually supplies a syntactically valid MAC. We explicitly refuse identity assertions from IP, hardware chipset, app name or firmware model. A cloud API device list that does not include a MAC is not automatically linked to a LAN device. The known household ANRAN camera still has **unverified Meari backend compatibility**.

**One-shot in-memory MAC comparison:** When an explicitly consented account attempt succeeds, Ocularium compares the returned catalog against only the saved, user-labeled ANRAN camera records for the *currently selected LAN scope*. No registry data is transmitted in account requests. The result provides **aggregate counts only**: exact one-to-one MAC matches, ambiguous duplicate MAC groups, saved records lacking usable MACs, saved records with no matching cloud MAC, and cloud cameras without usable MACs. Duplicate MACs on either side are deliberately ambiguous. Missing matches are inconclusive: MACs may be omitted by the backend, the camera may be saved under a different app, or the current scope may not contain it. This is not a device-stream capability claim. All comparison identifiers and catalog material are temporary; no account keys, IDs, or match outcomes are added to the registry or reports.

This is another protocol milestone, **not** working camera account discovery, live stream authentication, or proof of video access.

## ANRAN account handshake (experimental, one-shot opt-in)

The new native `src/meari_account.rs` implements an **explicit, three-stage** ANRAN wire exchange using the community profile's reported `sourceApp=84`, `partnerId=84`, app version and phone-type metadata. It constructs (1) redirect, (2) **one** login attempt, (3) an authenticated default device list, (4) an authenticated home-list query, and (5) at most **eight** signed per-home list requests, deduplicated and bounded. The read-only shared-home calls are modeled on the community reference's `GET /v1/app/home/list` and `GET /v1/app/home/join/device/list` with `homeID` and `funSwitch=1`. A recognized `1107` empty shared-home reply is not counted as a failure; malformed or rejected responses cause explicitly partial coverage without retries. Default and shared devices deduplicate only by authoritative `deviceID`. The legacy DES-CBC and AES-CBC compatibility formats, HMAC-SHA1 `X-Ca` request headers, and signed device-list form are checked against independently computed fixed-answer vectors. Failed login stops immediately; it never mutates the password or retries automatically.

The module's protocol logic is mockable and tested without touching any real camera or account. A native certificate-verifying HTTPS transport is exposed only via an **explicit one-shot consent gate**. Ordinary startup, LAN discovery and camera selection do not contact the cloud service. It enforces an allowlist of known Meari/CloudEdge host families, prohibits unvalidated redirect targets, disables proxies and HTTP redirects, bounds response size, and returns error categories rather than server bodies or credentials. Account/password and token values are short-lived `Zeroizing<String>` values in memory; the existing camera registry does not store them.

**Backend preflight (offline):** The panel starts with **Unknown / not checked** and keeps all account inputs hidden until the user explicitly selects **ANRAN app** *and* affirms that this particular camera appears in that app's device list. Other app choices remain blocked; switching choices clears existing credentials and consent. The checked app is transient and is **not** persisted as a verified hardware property. Only a subsequently authorized, authenticated device-list response can test whether the account backend actually contains the camera; it still cannot prove playable P2P video.

**GUI safety boundary:** Account and password fields are masked, held temporarily using zeroizing memory, and cleared from the GUI on submission. No login occurs unless the user explicitly authorizes that one attempt and acknowledges the potential mobile-session conflict. Only a redacted device-count, local-MAC-correlation and coverage summary or generic error reaches the UI; tokens, device IDs and camera keys are never exported or persisted. The temporary catalog is discarded after summarization. The client zeroizes its owned request-value, plaintext credential, response-byte and catalog-field buffers on release as a best-effort measure; the HTTP library and operating system can still create transient copies. No retries or background polling are implemented.

**Optional IoT platform config inspection (default OFF):** The ANRAN GUI exposes a separate checkbox for one signed, same-origin `GET /v2/app/config/pf/init?iotType=4` during an already-consented account lookup. It is never called by startup, LAN discovery, or ordinary account login unless this extra option is checked. The response may contain OpenAPI credentials, MQTT broker configuration, and encrypted platform signatures. Ocularium reads only non-secret **presence flags** (OpenAPI, MQTT, platform, encrypted-signature declared) into an aggregate summary; it neither decrypts the signature nor connects to any returned service address. Malformed data, an HTTP failure, or the vendor's transient `1023` response produce fixed statuses and **no retries**; default and shared-home discovery proceed independently. Platform bytes are transient, not saved or included in reports. Presence does not prove working P2P transport or connectivity.

**Current limitations:** The ANRAN community protocol may not match this particular device, some app logins may displace a concurrent mobile session, and a verified live account/device exchange has not been performed. The handshake now covers default and bounded shared-home camera lists and optional read-only IoT configuration inspection, but not platform credential decryption or P2P platform authorization. Responses can still be incomplete, for example after an unavailable home list or a cap of eight shared homes. A successful API response would still not prove video support or transport compatibility. This remains an experimental implementation, not an authorization to connect to any third-party account.

## Open engineering work

1. Validate a **specific** backend/device match for the ANRAN camera without logging into undocumented APIs from an untrusted client. Explicit user consent is required before any future account connection.
2. For a proven ANRAN integration, add reviewed, authorized P2P transport and VVP reassembly/decryption to deliver complete plaintext video frames into the existing offline elementary-stream/CPU decoder. A local MPEG-TS bridge is not required for this frame path; the separate generic MPEG-TS intake remains optional.
3. Identify a supported event-media export workflow for VicoHome. Full live access remains unavailable through documented open protocols.
4. Add continuous multi-camera playback and optional MCP snapshot access only when actual authorized video sources work and have clear access permissions.

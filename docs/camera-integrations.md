# Camera ecosystem integration research (2026-10-17)

This is technical planning, **not** a claim of working Ocularium app-account access or support for every camera.

## ANRAN

- Ocularium has a user-identified ANRAN camera; manufacturer branding and a mobile app name do **not** establish its protocol or cloud backend.
- ANRAN's own website distributes a mobile application and lists Windows/macOS camera software for some product lines: https://anran-cctv.com/pages/support-app-download
- **Experimental community lead:** https://github.com/raulrojas22/Ha-CloudPlus-Meari-ANRAN includes an ANRAN app profile and reverse-engineered CloudPlus/Meari P2P streaming. It is unofficial and not verified compatible with this household device. The repository's documentation notes cloud login, possible single-session conflicts, and optional video encryption codes. It is *not* an official ANRAN API.
- **Boundary for future adapter:** First establish whether the household ANRAN camera's app uses the supported backend and whether an owner-authorized account/device sharing flow exists. Do not accept app credentials in Ocularium until a supported protocol flow and safe credential lifecycle are implemented. Do not import external code without reviewing its license and security.

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

## Open engineering work

1. Validate a **specific** backend/device match for the ANRAN camera without logging into undocumented APIs from an untrusted client. Explicit user consent is required before any future account connection.
2. For a proven ANRAN integration, implement a reviewed, bounded in-process adapter to produce local MPEG-TS with no required Home Assistant or background server. The current generic intake can help test video decoding independently of account/API work.
3. Identify a supported event-media export workflow for VicoHome. Full live access remains unavailable through documented open protocols.
4. Add continuous multi-camera playback and optional MCP snapshot access only when actual authorized video sources work and have clear access permissions.

//! Native offline Meari/VVP primitives for a possible future ANRAN adapter.
//! Protocol layouts cross-checked against MIT-licensed
//! github.com/raulrojas22/Ha-CloudPlus-Meari-ANRAN
//! (p2p_streamer/protocol.py and codec.py, inspected 2026-10-17).
//! No cloud login, endpoint discovery, ICE, TURN, KCP, PPCS, decryption,
//! networking, or video playback is implemented in this module.

const MAGIC: u32 = 0x5656_5099;
const COMMAND_BYTES: usize = 60;
const MAX_FRAME: usize = 8 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transport {
    Ppcs,
    Signaling,
    Unknown,
}
impl Transport {
    /// Only an actual authenticated device-list record determines transport.
    /// LAN chipsets, model names and firmware cannot substitute for this.
    pub fn from_device_record(value: &serde_json::Value) -> Self {
        match value.get("deviceP2P").and_then(serde_json::Value::as_str) {
            Some(v) if v.eq_ignore_ascii_case("ppcs") => Self::Ppcs,
            Some(v) if !v.trim().is_empty() => Self::Signaling,
            _ => Self::Unknown,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Command {
    StartLive,
    Stop,
    Heartbeat,
}
impl Command {
    fn code(self) -> u32 {
        match self {
            Self::StartLive => 0x11ff,
            Self::Stop => 0x12ff,
            Self::Heartbeat => 0x888e,
        }
    }
}

/// Session parameters must come from a legitimately authenticated device
/// record. No Debug/Serialize implementation: do not expose host key or ID.
pub struct SessionAuth<'a> {
    pub host_key: &'a str,
    pub licence_id: Option<&'a str>,
}

pub struct CommandOptions {
    pub sequence: u32,
    pub parameter: u32,
    pub channel: u32,
    pub stream_id: u8,
    pub stream_flag: u8,
}

/// Prepare a 60-byte VVP command. This is an offline encoder: NO sending.
pub fn encode_command(
    auth: &SessionAuth<'_>,
    command: Command,
    options: &CommandOptions,
) -> Result<[u8; COMMAND_BYTES], &'static str> {
    if auth.host_key.is_empty() || auth.host_key.len() > 256 || !auth.host_key.is_ascii() {
        return Err("Invalid authenticated host key");
    }
    if auth.licence_id.is_some_and(|s| s.is_empty() || s.len() > 128 || !s.is_ascii()) {
        return Err("Invalid authenticated licence ID");
    }
    let key = if auth.host_key.len() > 32 {
        auth.host_key
    } else {
        &auth.host_key[..auth.host_key.len().min(16)]
    };
    let code = command.code();
    let mut material = format!(
        "admin|{key}|{MAGIC}|{}|{code}|{}|meari.p2p.ppcs",
        options.sequence, options.parameter
    );
    if let Some(licence_id) = auth.licence_id {
        material.push('|');
        material.push_str(licence_id);
    }
    let digest = format!("{:x}", md5::compute(material.as_bytes()));
    let mut bytes = [0; COMMAND_BYTES];
    bytes[0..4].copy_from_slice(&MAGIC.to_be_bytes());
    bytes[4..8].copy_from_slice(&1u32.to_be_bytes());
    bytes[8..12].copy_from_slice(&options.sequence.to_be_bytes());
    bytes[12..16].copy_from_slice(&code.to_be_bytes());
    bytes[16..48].copy_from_slice(digest.as_bytes());
    bytes[48..52].copy_from_slice(&options.parameter.to_be_bytes());
    bytes[52..56].copy_from_slice(&options.channel.to_le_bytes());
    bytes[56] = options.stream_id;
    bytes[57] = options.stream_flag;
    Ok(bytes)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FrameKind {
    Keyframe,
    Predicted,
    Audio,
    Info,
}
impl FrameKind {
    fn parse(marker: u8) -> Option<Self> {
        match marker {
            0xfc => Some(Self::Keyframe),
            0xfd => Some(Self::Predicted),
            0xfa => Some(Self::Audio),
            0xf9 => Some(Self::Info),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MediaFrame<'a> {
    pub kind: FrameKind,
    pub timestamp_ms: Option<u32>,
    pub sequence: Option<u32>,
    pub payload: &'a [u8],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FrameError {
    Incomplete,
    Invalid,
    Oversized,
    MissingLength,
}

fn le_u32(bytes: &[u8], pos: usize) -> u32 {
    u32::from_le_bytes(bytes[pos..pos + 4].try_into().expect("validated header length"))
}

/// Parse one plaintext frame from already reassembled media bytes. No
/// decryption is performed; encrypted frames must be handled separately.
/// Returns the bytes consumed, so concatenated frames can be parsed.
pub fn parse_frame(data: &[u8]) -> Result<(MediaFrame<'_>, usize), FrameError> {
    if data.len() < 8 {
        return Err(FrameError::Incomplete);
    }
    if data[0..3] != [0, 0, 1] {
        return Err(FrameError::Invalid);
    }
    let kind = FrameKind::parse(data[3]).ok_or(FrameError::Invalid)?;
    let (header_size, payload_len, timestamp_ms, sequence) = match kind {
        FrameKind::Keyframe => {
            if data.len() < 0x3c { return Err(FrameError::Incomplete); }
            (0x3c, le_u32(data, 0x38) as usize, Some(le_u32(data, 0x30)), Some(le_u32(data, 0x10)))
        }
        FrameKind::Predicted => {
            if data.len() < 0x34 { return Err(FrameError::Incomplete); }
            (0x34, le_u32(data, 0x30) as usize, Some(le_u32(data, 0x28)), Some(le_u32(data, 0x08)))
        }
        FrameKind::Audio => {
            if data.len() < 0x34 { return Err(FrameError::Incomplete); }
            (0x34, le_u32(data, 0x30) as usize, Some(le_u32(data, 0x28)), None)
        }
        FrameKind::Info => {
            (8, u16::from_le_bytes([data[6], data[7]]) as usize, None, None)
        }
    };
    if payload_len == 0 { return Err(FrameError::MissingLength); }
    if payload_len > MAX_FRAME { return Err(FrameError::Oversized); }
    let end = header_size.checked_add(payload_len).ok_or(FrameError::Oversized)?;
    let payload = data.get(header_size..end).ok_or(FrameError::Incomplete)?;
    Ok((MediaFrame { kind, timestamp_ms, sequence, payload }, end))
}

#[derive(Clone, Debug)]
pub struct SequenceGate {
    last: Option<u32>,
    needs_keyframe: bool,
}
impl Default for SequenceGate {
    fn default() -> Self {
        Self { last: None, needs_keyframe: true }
    }
}
impl SequenceGate {
    pub fn reset(&mut self) {
        self.last = None;
        self.needs_keyframe = true;
    }
    pub fn accept(&mut self, frame: &MediaFrame<'_>) -> bool {
        if !matches!(frame.kind, FrameKind::Keyframe | FrameKind::Predicted) {
            return true;
        }
        if self.needs_keyframe && frame.kind != FrameKind::Keyframe { return false; }
        if let (Some(previous), Some(seq)) = (self.last, frame.sequence) {
            let delta = seq.wrapping_sub(previous);
            if delta == 0 || delta > 0x8000_0000 { return false; }
        }
        self.last = frame.sequence;
        if frame.kind == FrameKind::Keyframe { self.needs_keyframe = false; }
        !self.needs_keyframe
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frame(kind: FrameKind, sequence: u32, payload: &[u8]) -> Vec<u8> {
        let size = match kind {
            FrameKind::Keyframe => 0x3c,
            FrameKind::Predicted | FrameKind::Audio => 0x34,
            FrameKind::Info => 8,
        };
        let mut out = vec![0u8; size + payload.len()];
        out[..3].copy_from_slice(&[0,0,1]);
        out[3] = match kind {
            FrameKind::Keyframe => 0xfc,
            FrameKind::Predicted => 0xfd,
            FrameKind::Audio => 0xfa,
            FrameKind::Info => 0xf9,
        };
        match kind {
            FrameKind::Keyframe => {
                out[0x10..0x14].copy_from_slice(&sequence.to_le_bytes());
                out[0x30..0x34].copy_from_slice(&12345u32.to_le_bytes());
                out[0x38..0x3c].copy_from_slice(&(payload.len() as u32).to_le_bytes());
            }
            FrameKind::Predicted | FrameKind::Audio => {
                out[0x08..0x0c].copy_from_slice(&sequence.to_le_bytes());
                out[0x28..0x2c].copy_from_slice(&12345u32.to_le_bytes());
                out[0x30..0x34].copy_from_slice(&(payload.len() as u32).to_le_bytes());
            }
            FrameKind::Info => out[6..8].copy_from_slice(&(payload.len() as u16).to_le_bytes()),
        }
        out[size..].copy_from_slice(payload);
        out
    }

    #[test]
    fn no_guessed_transport_from_platform() {
        assert_eq!(Transport::from_device_record(&serde_json::json!({"deviceP2P":"ppcs"})), Transport::Ppcs);
        assert_eq!(Transport::from_device_record(&serde_json::json!({"deviceP2P":"PPCS"})), Transport::Ppcs);
        assert_eq!(Transport::from_device_record(&serde_json::json!({"deviceP2P":"webrtc"})), Transport::Signaling);
        assert_eq!(Transport::from_device_record(&serde_json::json!({"platform":"b81"})), Transport::Unknown);
        assert_eq!(Transport::from_device_record(&serde_json::json!({})), Transport::Unknown);
    }

    #[test]
    fn vvp_start_live_known_digest_and_wire_layout() {
        let auth = SessionAuth { host_key: "testing-only-host-key", licence_id: Some("TEST-DEVICE-0001") };
        let settings = CommandOptions { sequence: 7, parameter: 8, channel: 0, stream_id: 105, stream_flag: 1 };
        let bytes = encode_command(&auth, Command::StartLive, &settings).unwrap();
        assert_eq!(&bytes[0..4], &[0x56, 0x56, 0x50, 0x99]);
        assert_eq!(u32::from_be_bytes(bytes[12..16].try_into().unwrap()), 0x11ff);
        assert_eq!(&bytes[16..48], b"fae311f6efefda4d33db0998df288273");
        assert_eq!(&bytes[48..52], &[0,0,0,8]);
        assert_eq!(&bytes[56..60], &[105,1,0,0]);
        assert!(encode_command(&SessionAuth { host_key: "", licence_id: None }, Command::Stop, &settings).is_err());
    }

    #[test]
    fn media_parser_handles_concatenated_frames_without_overreads() {
        let a = frame(FrameKind::Keyframe, 10, &[0,0,1,0x67]);
        let b = frame(FrameKind::Predicted, 11, &[0,0,1,0x41]);
        let c = frame(FrameKind::Info, 0, &[42]);
        let data: Vec<u8> = [a,b,c].concat();
        let mut tail = data.as_slice();
        let mut kinds = Vec::new();
        while !tail.is_empty() {
            let (packet, consumed) = parse_frame(tail).unwrap();
            kinds.push(packet.kind);
            if packet.kind == FrameKind::Keyframe {
                assert_eq!(packet.sequence, Some(10));
                assert_eq!(packet.timestamp_ms, Some(12345));
            }
            tail = &tail[consumed..];
        }
        assert_eq!(kinds, vec![FrameKind::Keyframe, FrameKind::Predicted, FrameKind::Info]);
    }

    #[test]
    fn media_parser_rejects_truncation_and_oversize() {
        assert_eq!(parse_frame(&[0;3]), Err(FrameError::Incomplete));
        assert_eq!(parse_frame(&[0;8]), Err(FrameError::Invalid));
        let a = frame(FrameKind::Keyframe, 5, &[1,2,3]);
        assert_eq!(parse_frame(&a[..0x18]), Err(FrameError::Incomplete));
        assert_eq!(parse_frame(&a[..a.len()-1]), Err(FrameError::Incomplete));
        let mut big = a.clone();
        big[0x38..0x3c].copy_from_slice(&((MAX_FRAME as u32)+1).to_le_bytes());
        assert_eq!(parse_frame(&big), Err(FrameError::Oversized));
        let mut no_len = a;
        no_len[0x38..0x3c].copy_from_slice(&0u32.to_le_bytes());
        assert_eq!(parse_frame(&no_len), Err(FrameError::MissingLength));
    }

    #[test]
    fn sequence_gate_requires_keyframe_and_prevents_replays() {
        let k = frame(FrameKind::Keyframe, u32::MAX, &[1]);
        let p = frame(FrameKind::Predicted, 0, &[2]);
        let b = frame(FrameKind::Predicted, u32::MAX-1, &[2]);
        let (key, _) = parse_frame(&k).unwrap();
        let (next, _) = parse_frame(&p).unwrap();
        let (back, _) = parse_frame(&b).unwrap();
        let mut gate = SequenceGate::default();
        assert!(!gate.accept(&next)); // startup is keyframe-gated too
        gate.reset();
        assert!(!gate.accept(&next));
        assert!(gate.accept(&key));
        assert!(gate.accept(&next));
        assert!(!gate.accept(&next));
        assert!(!gate.accept(&back));
    }
}

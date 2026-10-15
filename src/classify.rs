//! Evidence-first device classification.
//!
//! MAC OUI identifies the network chipset vendor, not necessarily the camera
//! maker.  Ports and RTSP responses are evidence of services, not playable
//! video. Classification deliberately avoids treating either as proof of a
//! physical camera.
use crate::discovery::Device;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeviceCategory {
    CameraCandidate,
    IdentifiedEquipment,
    Unidentified,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EvidenceLevel {
    DeviceDescription,
    ProtocolResponse,
    ServiceAdvertisement,
    OpenPort,
    NoTypeEvidence,
}

impl EvidenceLevel {
    pub fn label(self) -> &'static str {
        match self {
            Self::DeviceDescription => "Device description",
            Self::ProtocolResponse => "Protocol verified",
            Self::ServiceAdvertisement => "Service advertised",
            Self::OpenPort => "Port only",
            Self::NoTypeEvidence => "Not identified",
        }
    }
}

#[derive(Clone, Debug)]
pub struct Classification {
    pub category: DeviceCategory,
    pub label: &'static str,
    pub level: EvidenceLevel,
    /// Grounds the classification. Does not include speculation from OUI.
    pub reason: String,
}

impl Classification {
    fn new(
        category: DeviceCategory,
        label: &'static str,
        level: EvidenceLevel,
        reason: impl Into<String>,
    ) -> Self {
        Self {
            category,
            label,
            level,
            reason: reason.into(),
        }
    }

    pub fn camera_candidate(&self) -> bool {
        self.category == DeviceCategory::CameraCandidate
    }

    pub fn needs_identification(&self) -> bool {
        self.category == DeviceCategory::Unidentified
    }
}

pub fn classify(device: &Device) -> Classification {
    use DeviceCategory::{CameraCandidate, IdentifiedEquipment, Unidentified};
    use EvidenceLevel::{
        DeviceDescription, NoTypeEvidence, OpenPort, ProtocolResponse, ServiceAdvertisement,
    };

    // Explicit video device identities take priority, even when other
    // services happen to be present on the same IP.
    if device.onvif_types.iter().any(|kind| {
        kind.to_ascii_lowercase()
            .contains("networkvideotransmitter")
    }) {
        return Classification::new(
            CameraCandidate,
            "ONVIF camera",
            ServiceAdvertisement,
            "ONVIF WS-Discovery advertises NetworkVideoTransmitter",
        );
    }
    if let Some(identity) = device.identities.iter().find(|info| info.source == "ONVIF") {
        let model = identity.model.as_deref().unwrap_or("unnamed device");
        return Classification::new(
            CameraCandidate,
            "ONVIF device",
            DeviceDescription,
            format!("ONVIF GetDeviceInformation identified {model}; video not yet verified"),
        );
    }
    if let Some(identity) = device.identities.iter().find(|info| info.camera_hint()) {
        return Classification::new(
            CameraCandidate,
            "Camera-described device",
            DeviceDescription,
            format!(
                "{} description contains a camera-related type, model, or name",
                identity.source
            ),
        );
    }

    // These are actual UPnP device-type declarations.  They are not inferred
    // from a Wi-Fi chip vendor or from common TCP port numbers.
    for identity in &device.identities {
        if let Some(kind) = &identity.device_type {
            let lower = kind.to_ascii_lowercase();
            for (needle, label) in [
                ("internetgatewaydevice", "Router / gateway"),
                ("wanconnectiondevice", "Router / gateway"),
                ("wandevice", "Router / gateway"),
                ("mediaserver", "Media server"),
                ("mediarenderer", "Media renderer"),
                ("printer", "Printer"),
                ("scanner", "Scanner"),
                ("networkstorage", "Network storage"),
                ("basicdevice", "UPnP device"),
            ] {
                if lower.contains(needle) {
                    return Classification::new(
                        IdentifiedEquipment,
                        label,
                        DeviceDescription,
                        format!("{} advertises device type {kind}", identity.source),
                    );
                }
            }
        }
    }

    // Reaching an RTSP server means the protocol answered.  It does not
    // establish camera identity, credentials, stream path or decodability.
    if device.rtsp_responded {
        return Classification::new(
            CameraCandidate,
            "RTSP service",
            ProtocolResponse,
            "RTSP OPTIONS returned a valid protocol response; video not verified",
        );
    }
    if !device.onvif_xaddrs.is_empty() {
        return Classification::new(
            CameraCandidate,
            "ONVIF endpoint",
            ServiceAdvertisement,
            "ONVIF WS-Discovery provided a device-service address",
        );
    }
    if let Some(info) = device.http.iter().find(|info| info.camera_hint()) {
        return Classification::new(
            CameraCandidate,
            "Camera web interface",
            ServiceAdvertisement,
            format!(
                "HTTP metadata on port {} contains a camera-specific fingerprint",
                info.port
            ),
        );
    }
    if let Some(service) = device.mdns_services.iter().find(|service| {
        let lower = service.to_ascii_lowercase();
        lower.contains("_rtsp._tcp")
            || lower.contains("_onvif._tcp")
            || lower.contains("_axis-video._tcp")
    }) {
        return Classification::new(
            CameraCandidate,
            "Camera service advertised",
            ServiceAdvertisement,
            format!("mDNS advertises {service}; video not verified"),
        );
    }

    // Identifiable software running on a host does not establish the hardware
    // model.  Describe it as a service, not a physical device.
    if let Some(info) = device.http.iter().find(|info| {
        info.title
            .as_deref()
            .is_some_and(|title| title.to_ascii_lowercase().contains("calibre library"))
    }) {
        return Classification::new(
            IdentifiedEquipment,
            "Calibre service",
            ServiceAdvertisement,
            format!(
                "HTTP title on port {} identifies Calibre Library",
                info.port
            ),
        );
    }

    if let Some(port) = device
        .open_ports
        .iter()
        .find(|port| [554, 8554, 8899, 34567].contains(port))
    {
        return Classification::new(
            CameraCandidate,
            "Possible camera",
            OpenPort,
            format!("TCP port {port} is open; no camera protocol response confirmed"),
        );
    }
    if let Some(target) = device
        .ssdp_target
        .as_deref()
        .filter(|target| target.to_ascii_lowercase().contains("camera"))
    {
        return Classification::new(
            CameraCandidate,
            "Possible camera",
            ServiceAdvertisement,
            format!("SSDP search target contains camera: {target}"),
        );
    }

    Classification::new(Unidentified, "Unidentified device", NoTypeEvidence,
        "No device-type declaration or camera-specific protocol evidence. A MAC vendor alone cannot identify the hardware.")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::discovery::{Device, Observation};
    use crate::identity::IdentityInfo;
    use std::net::Ipv4Addr;

    fn device() -> Device {
        Device::new(Ipv4Addr::new(192, 168, 0, 1))
    }

    fn identity(device_type: &str, model: &str) -> IdentityInfo {
        IdentityInfo {
            source: "UPnP/SSDP",
            friendly_name: None,
            manufacturer: Some("TP-Link".to_owned()),
            model: Some(model.to_owned()),
            model_number: None,
            device_type: Some(device_type.to_owned()),
            firmware: None,
        }
    }

    #[test]
    fn router_is_identified_from_upnp_description() {
        let mut d = device();
        d.apply(Observation::Identity(identity(
            "urn:schemas-upnp-org:device:InternetGatewayDevice:1",
            "TL-WR840N",
        )));
        d.apply(Observation::Vendor("TP-Link Systems Inc".into()));
        let result = classify(&d);
        assert_eq!(result.label, "Router / gateway");
        assert_eq!(result.level, EvidenceLevel::DeviceDescription);
        assert!(!result.camera_candidate());
        assert!(result.reason.contains("InternetGatewayDevice"));
    }

    #[test]
    fn wifi_chip_vendor_does_not_imply_camera() {
        let mut d = device();
        d.apply(Observation::Vendor("Sichuan AI-Link Technology".into()));
        assert_eq!(classify(&d).label, "Unidentified device");
        assert!(classify(&d).needs_identification());
    }

    #[test]
    fn rtsp_protocol_is_camera_candidate_not_confirmed_video() {
        let mut d = device();
        d.apply(Observation::OpenPorts {
            ports: vec![8554],
            rtsp_responded: true,
        });
        let result = classify(&d);
        assert_eq!(result.label, "RTSP service");
        assert!(result.camera_candidate());
        assert_eq!(result.level, EvidenceLevel::ProtocolResponse);
    }

    #[test]
    fn port_without_rtsp_response_is_only_a_hint() {
        let mut d = device();
        d.apply(Observation::OpenPorts {
            ports: vec![554],
            rtsp_responded: false,
        });
        assert_eq!(classify(&d).level, EvidenceLevel::OpenPort);
    }

    #[test]
    fn onvif_video_signal_wins_over_generic_gateway() {
        let mut d = device();
        d.apply(Observation::Identity(identity(
            "urn:schemas-upnp-org:device:InternetGatewayDevice:1",
            "Gateway",
        )));
        d.apply(Observation::Onvif {
            xaddrs: vec![],
            scopes: vec![],
            types: vec!["dn:NetworkVideoTransmitter".into()],
        });
        assert_eq!(classify(&d).label, "ONVIF camera");
    }

    #[test]
    fn mediaserver_type_not_a_camera() {
        let mut d = device();
        d.apply(Observation::Identity(identity(
            "urn:schemas-upnp-org:device:MediaServer:1",
            "Library",
        )));
        assert_eq!(classify(&d).label, "Media server");
        assert!(!classify(&d).camera_candidate());
    }
}

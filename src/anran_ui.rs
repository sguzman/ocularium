//! Opt-in ANRAN account discovery panel. Never connects at startup or during LAN scans.
//! Unverified community protocol: a login may displace an existing mobile session.

use std::{
    sync::mpsc::{self, Receiver, TryRecvError},
    thread,
};

use eframe::egui;
use zeroize::Zeroizing;

use crate::{
    meari_account::{self, AuthError, Credentials},
    meari_devices::CatalogSummary,
};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
enum PairedApp {
    #[default]
    Unknown,
    Anran,
    CloudEdge,
    Arcctv,
    Eseecloud,
    Other,
}

impl PairedApp {
    const ALL: [Self; 6] = [
        Self::Unknown,
        Self::Anran,
        Self::CloudEdge,
        Self::Arcctv,
        Self::Eseecloud,
        Self::Other,
    ];

    fn label(self) -> &'static str {
        match self {
            Self::Unknown => "Unknown / not checked",
            Self::Anran => "ANRAN app",
            Self::CloudEdge => "CloudEdge app",
            Self::Arcctv => "ARCCTV app",
            Self::Eseecloud => "EseeCloud app",
            Self::Other => "Other app",
        }
    }

    fn supported_by_client(self) -> bool {
        // This client sends only ANRAN's sourceApp=84 wire identity.
        // An ANRAN-branded camera can use an entirely different app.
        self == Self::Anran
    }
}

pub struct AnranPanel {
    account: Zeroizing<String>,
    password: Zeroizing<String>,
    country: String,
    dialing_code: String,
    paired_app: PairedApp,
    camera_listed_in_app: bool,
    consent: bool,
    rx: Option<Receiver<Result<CatalogSummary, AuthError>>>,
    result: Option<Result<CatalogSummary, AuthError>>,
}

impl Default for AnranPanel {
    fn default() -> Self {
        Self {
            account: Zeroizing::new(String::new()),
            password: Zeroizing::new(String::new()),
            country: "MX".into(),
            dialing_code: "52".into(),
            paired_app: PairedApp::Unknown,
            camera_listed_in_app: false,
            consent: false,
            rx: None,
            result: None,
        }
    }
}

fn valid(account: &str, password: &str, country: &str, dialing_code: &str) -> bool {
    !account.is_empty()
        && account.len() <= 254
        && !password.is_empty()
        && password.len() <= 256
        && country.len() == 2
        && country.bytes().all(|b| b.is_ascii_uppercase())
        && (1..=4).contains(&dialing_code.len())
        && dialing_code.bytes().all(|b| b.is_ascii_digit())
}

fn error_text(error: AuthError) -> &'static str {
    match error {
        AuthError::InvalidInput => "Invalid account or region fields.",
        AuthError::InvalidServer => "Unrecognized server or redirect; stopped.",
        AuthError::InvalidReply => "Unrecognized server response; stopped.",
        AuthError::LoginRejected => "Login rejected; no retry.",
        AuthError::DeviceListRejected => "No verified device list.",
        AuthError::Transport => "HTTPS request failed; no retry.",
    }
}

impl AnranPanel {
    pub fn busy(&self) -> bool {
        self.rx.is_some()
    }

    fn set_paired_app(&mut self, new_app: PairedApp) {
        if self.busy() || new_app == self.paired_app {
            return;
        }
        self.paired_app = new_app;
        // Do not carry consent or entered credentials across app families.
        self.account.clear();
        self.password.clear();
        self.consent = false;
        self.camera_listed_in_app = false;
        self.result = None;
    }

    pub fn poll(&mut self) {
        if let Some(rx) = self.rx.take() {
            match rx.try_recv() {
                Ok(result) => self.result = Some(result),
                Err(TryRecvError::Empty) => self.rx = Some(rx),
                Err(TryRecvError::Disconnected) => {
                    self.result = Some(Err(AuthError::Transport));
                }
            }
        }
    }

    fn ready(&self) -> bool {
        !self.busy()
            && self.paired_app.supported_by_client()
            && self.camera_listed_in_app
            && self.consent
            && valid(
                self.account.as_str(),
                self.password.as_str(),
                &self.country,
                &self.dialing_code,
            )
    }

    // Independent of transport: unit tests can prove that this gate never
    // hands credentials to a worker without fresh, explicit consent.
    fn take_consented_credentials(&mut self) -> Option<Credentials> {
        if !self.ready() {
            return None;
        }
        let credentials = Credentials {
            account: std::mem::replace(&mut self.account, Zeroizing::new(String::new())),
            password: std::mem::replace(&mut self.password, Zeroizing::new(String::new())),
            country: self.country.clone(),
            phone_code: self.dialing_code.clone(),
        };
        self.consent = false;
        self.result = None;
        Some(credentials)
    }

    fn start(&mut self) {
        let Some(credentials) = self.take_consented_credentials() else {
            return;
        };
        let (tx, rx) = mpsc::channel();
        self.rx = Some(rx);
        thread::spawn(move || {
            let result = meari_account::discover_account(
                &mut meari_account::HttpsExchange::default(),
                &mut meari_account::SystemClock,
                credentials,
            )
            .map(|catalog| catalog.summary());
            let _ = tx.send(result);
        });
    }

    pub fn ui(&mut self, ui: &mut egui::Ui) {
        egui::CollapsingHeader::new("ANRAN account discovery (experimental)")
            .default_open(false)
            .show(ui, |ui| {
                ui.label("Unofficial Meari/CloudPlus backend. Compatibility unverified.");
                ui.label(
                    "A login may invalidate the mobile app session. Only use an account you control.",
                );
                ui.label("One request sequence, no automatic retries or saved credentials.");
                ui.small("Country and dialing code must match the account registration region.");
                let busy = self.busy();
                let mut selected_app = self.paired_app;
                ui.horizontal(|ui| {
                    ui.label("App where this camera is paired");
                    ui.add_enabled_ui(!busy, |ui| {
                        egui::ComboBox::from_id_salt("anran_account_app_choice")
                            .selected_text(selected_app.label())
                            .show_ui(ui, |ui| {
                                for app in PairedApp::ALL {
                                    ui.selectable_value(&mut selected_app, app, app.label());
                                }
                            });
                    });
                });
                self.set_paired_app(selected_app);
                if !self.paired_app.supported_by_client() {
                    ui.label(
                        "This experimental login uses the ANRAN app profile only. \
                         The camera brand or model does not identify its account backend.",
                    );
                    ui.small(
                        "ANRAN also sells cameras for ARCCTV/CloudEdge ecosystems. \
                         Select the app where the camera actually appears, not its brand.",
                    );
                    return;
                }
                ui.add_enabled_ui(!busy, |ui| {
                    ui.checkbox(
                        &mut self.camera_listed_in_app,
                        "I verified this camera is listed in my ANRAN app account",
                    );
                });
                if !self.camera_listed_in_app {
                    ui.small(
                        "No network request. Confirm the paired app first; app identity \
                         alone still does not verify camera P2P transport.",
                    );
                    return;
                }
                ui.separator();
                ui.horizontal(|ui| {
                    ui.label("Country");
                    ui.add_enabled(
                        !busy,
                        egui::TextEdit::singleline(&mut self.country).desired_width(45.0),
                    );
                    ui.label("Dial code");
                    ui.add_enabled(
                        !busy,
                        egui::TextEdit::singleline(&mut self.dialing_code).desired_width(45.0),
                    );
                });
                ui.horizontal(|ui| {
                    ui.label("Account");
                    ui.add_enabled(
                        !busy,
                        egui::TextEdit::singleline(&mut *self.account)
                            .password(true)
                            .desired_width(240.0),
                    );
                });
                ui.horizontal(|ui| {
                    ui.label("Password");
                    ui.add_enabled(
                        !busy,
                        egui::TextEdit::singleline(&mut *self.password)
                            .password(true)
                            .desired_width(240.0),
                    );
                });
                ui.add_enabled_ui(!busy, |ui| {
                    ui.checkbox(
                        &mut self.consent,
                        "I authorize this login and accept possible mobile session logout",
                    );
                });
                ui.horizontal(|ui| {
                    if ui
                        .add_enabled(
                            self.ready(),
                            egui::Button::new("Connect once and count devices"),
                        )
                        .clicked()
                    {
                        self.start();
                    }
                    if ui
                        .add_enabled(!busy, egui::Button::new("Clear credentials and result"))
                        .clicked()
                    {
                        self.account.clear();
                        self.password.clear();
                        self.consent = false;
                        self.result = None;
                    }
                });
                if busy {
                    ui.spinner();
                    ui.label("Connecting once; no automatic retry.");
                }
                if let Some(result) = self.result {
                    match result {
                        Ok(counts) => {
                            ui.label(counts.safe_text());
                            ui.label(
                                "Device IDs, keys and access tokens were not retained in the UI.",
                            );
                        }
                        Err(error) => {
                            ui.label(error_text(error));
                        }
                    }
                }
            });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn anran_brand_never_implies_anran_app_backend() {
        let all = PairedApp::ALL;
        assert_eq!(
            all.iter().filter(|app| app.supported_by_client()).count(),
            1
        );
        assert!(PairedApp::Anran.supported_by_client());
        assert!(!PairedApp::Unknown.supported_by_client());
        assert!(!PairedApp::CloudEdge.supported_by_client());
        assert!(!PairedApp::Arcctv.supported_by_client());
        assert!(!PairedApp::Eseecloud.supported_by_client());
        assert!(!PairedApp::Other.supported_by_client());
    }

    #[test]
    fn switching_app_resets_credential_state_and_consent() {
        let mut panel = AnranPanel {
            paired_app: PairedApp::Anran,
            camera_listed_in_app: true,
            account: Zeroizing::new("sample@example.invalid".into()),
            password: Zeroizing::new("sample".into()),
            consent: true,
            ..Default::default()
        };
        assert!(panel.ready());
        panel.set_paired_app(PairedApp::Arcctv);
        assert_eq!(panel.paired_app, PairedApp::Arcctv);
        assert!(!panel.camera_listed_in_app);
        assert!(!panel.consent);
        assert!(panel.account.is_empty());
        assert!(panel.password.is_empty());
        panel.set_paired_app(PairedApp::Anran);
        assert!(!panel.ready());
    }

    #[test]
    fn explicit_consent_and_region_required() {
        let mut panel = AnranPanel {
            account: Zeroizing::new("sample@example.invalid".into()),
            password: Zeroizing::new("sample".into()),
            paired_app: PairedApp::Anran,
            camera_listed_in_app: true,
            ..Default::default()
        };
        assert!(!panel.ready());
        panel.consent = true;
        assert!(panel.ready());
        panel.country = "mx".into();
        assert!(!panel.ready());
    }

    #[test]
    fn no_consent_means_credentials_never_leave_the_form() {
        let mut panel = AnranPanel {
            account: Zeroizing::new("sample@example.invalid".into()),
            password: Zeroizing::new("sample".into()),
            paired_app: PairedApp::Anran,
            camera_listed_in_app: true,
            ..Default::default()
        };
        assert!(panel.take_consented_credentials().is_none());
        assert_eq!(panel.account.as_str(), "sample@example.invalid");
        assert_eq!(panel.password.as_str(), "sample");
        assert!(!panel.busy());
    }

    #[test]
    fn authorized_credentials_are_taken_once_and_the_form_cleared() {
        let mut panel = AnranPanel {
            account: Zeroizing::new("sample@example.invalid".into()),
            password: Zeroizing::new("sample".into()),
            paired_app: PairedApp::Anran,
            camera_listed_in_app: true,
            consent: true,
            ..Default::default()
        };
        let credentials = panel.take_consented_credentials().unwrap();
        assert_eq!(credentials.account.as_str(), "sample@example.invalid");
        assert_eq!(credentials.password.as_str(), "sample");
        assert!(panel.account.is_empty());
        assert!(panel.password.is_empty());
        assert!(!panel.consent);
        assert!(panel.take_consented_credentials().is_none());
        assert!(!panel.busy());
    }

    #[test]
    fn consent_cannot_override_unverified_or_unsupported_app() {
        let mut panel = AnranPanel {
            account: Zeroizing::new("sample@example.invalid".into()),
            password: Zeroizing::new("sample".into()),
            consent: true,
            ..Default::default()
        };
        assert!(!panel.ready());
        panel.camera_listed_in_app = true;
        assert!(!panel.ready());
        for other_app in [
            PairedApp::CloudEdge,
            PairedApp::Arcctv,
            PairedApp::Eseecloud,
            PairedApp::Other,
        ] {
            panel.paired_app = other_app;
            assert!(panel.take_consented_credentials().is_none());
        }
        panel.paired_app = PairedApp::Anran;
        assert!(panel.ready());
    }

    #[test]
    fn busy_or_invalid_inputs_never_handoff_credentials() {
        let mut panel = AnranPanel {
            account: Zeroizing::new("sample@example.invalid".into()),
            password: Zeroizing::new("sample".into()),
            paired_app: PairedApp::Anran,
            camera_listed_in_app: true,
            consent: true,
            ..Default::default()
        };
        panel.dialing_code = "5x".into();
        assert!(panel.take_consented_credentials().is_none());
        panel.dialing_code = "52".into();
        let (_sender, receiver) = mpsc::channel();
        panel.rx = Some(receiver);
        assert!(panel.take_consented_credentials().is_none());
    }
}

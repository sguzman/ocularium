//! Opt-in ANRAN account discovery panel. Never connects at startup or during LAN scans.
//! Unverified community protocol: a login may displace an existing mobile session.

use std::{
    sync::mpsc::{self, Receiver, TryRecvError},
    thread,
};

use eframe::egui;
use zeroize::{Zeroize, Zeroizing};

use crate::{
    anran_keyring::{self, Account as KeyringAccount, Error as KeyringError},
    meari_account::{
        self, AuthError, Credentials, DeviceListDiagnostic, DiscoveryCoverage, DiscoveryOptions,
        PlatformSummary,
    },
    meari_devices::{CatalogCorrelation, CatalogSummary, MatchedPpcsSummary, PpcsMetadataSummary},
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

/// Only counts cross the worker boundary. No account IDs, MACs, device
/// keys, network addresses, or raw server responses reach this UI.
#[derive(Clone, Copy)]
struct DiscoveryReport {
    catalog: CatalogSummary,
    correlation: CatalogCorrelation,
    ppcs_metadata: PpcsMetadataSummary,
    matched_ppcs: MatchedPpcsSummary,
    coverage: DiscoveryCoverage,
    diagnostic: DeviceListDiagnostic,
    platform: PlatformSummary,
}

enum KeyringReply {
    Loaded(Result<Option<KeyringAccount>, KeyringError>),
    Saved(Result<(), KeyringError>),
    Deleted(Result<(), KeyringError>),
}

pub struct AnranPanel {
    account: Zeroizing<String>,
    password: Zeroizing<String>,
    country: String,
    dialing_code: String,
    paired_app: PairedApp,
    camera_listed_in_app: bool,
    inspect_platform: bool,
    consent: bool,
    rx: Option<Receiver<Result<DiscoveryReport, AuthError>>>,
    result: Option<Result<DiscoveryReport, AuthError>>,
    keyring_rx: Option<Receiver<(u64, KeyringReply)>>,
    keyring_epoch: u64,
    keyring_restore_pending: bool,
    keyring_message: Option<&'static str>,
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
            inspect_platform: false,
            consent: false,
            rx: None,
            result: None,
            keyring_rx: None,
            keyring_epoch: 0,
            keyring_restore_pending: false,
            keyring_message: None,
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

fn error_text(error: AuthError) -> String {
    match error {
        AuthError::DeviceListUnavailable(diagnostic) => diagnostic.safe_text(),
        AuthError::HttpStatus(status) => {
            format!("HTTPS request failed: {}; no retry.", status.safe_label())
        }
        other => match other {
            AuthError::InvalidInput => "Invalid account or region fields.",
            AuthError::InvalidServer => "Unrecognized server or redirect; stopped.",
            AuthError::InvalidReply => "Unrecognized server response; stopped.",
            AuthError::LoginRejected => "Login rejected; no retry.",
            AuthError::DeviceListRejected => "Device list rejected; no retry.",
            AuthError::Transport => "HTTPS request failed; no retry.",
            AuthError::DeviceListUnavailable(_) | AuthError::HttpStatus(_) => unreachable!(),
        }
        .to_owned(),
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
        self.keyring_epoch = self.keyring_epoch.wrapping_add(1);
        self.keyring_restore_pending = new_app == PairedApp::Anran;
        self.keyring_message = None;
        // Do not carry consent or entered credentials across app families.
        self.account.clear();
        self.password.clear();
        self.consent = false;
        self.camera_listed_in_app = false;
        self.inspect_platform = false;
        self.result = None;
    }

    fn start_keyring_restore(&mut self) {
        if self.keyring_rx.is_some() || self.paired_app != PairedApp::Anran {
            return;
        }
        self.keyring_restore_pending = false;
        let epoch = self.keyring_epoch;
        let (tx, rx) = mpsc::channel();
        self.keyring_rx = Some(rx);
        thread::spawn(move || {
            let _ = tx.send((epoch, KeyringReply::Loaded(anran_keyring::load())));
        });
    }

    fn save_keyring(&mut self) {
        if self.busy()
            || self.keyring_rx.is_some()
            || self.paired_app != PairedApp::Anran
            || !valid(
                &self.account,
                &self.password,
                &self.country,
                &self.dialing_code,
            )
        {
            return;
        }
        let data = KeyringAccount {
            username: Zeroizing::new((*self.account).clone()),
            password: Zeroizing::new((*self.password).clone()),
            country: self.country.clone(),
            dial_code: self.dialing_code.clone(),
        };
        self.keyring_message = None;
        self.keyring_restore_pending = false;
        let epoch = self.keyring_epoch;
        let (tx, rx) = mpsc::channel();
        self.keyring_rx = Some(rx);
        thread::spawn(move || {
            let _ = tx.send((epoch, KeyringReply::Saved(anran_keyring::save(data))));
        });
    }

    fn delete_keyring(&mut self) {
        if self.busy() || self.keyring_rx.is_some() || self.paired_app != PairedApp::Anran {
            return;
        }
        self.keyring_message = None;
        self.keyring_restore_pending = false;
        let epoch = self.keyring_epoch;
        let (tx, rx) = mpsc::channel();
        self.keyring_rx = Some(rx);
        thread::spawn(move || {
            let _ = tx.send((epoch, KeyringReply::Deleted(anran_keyring::delete())));
        });
    }

    fn poll_keyring(&mut self) {
        if let Some(rx) = self.keyring_rx.take() {
            match rx.try_recv() {
                Ok((epoch, reply))
                    if epoch == self.keyring_epoch && self.paired_app == PairedApp::Anran =>
                {
                    match reply {
                        KeyringReply::Loaded(Ok(Some(account))) => {
                            // Only restore empty fields; never overwrite manual edits.
                            if self.account.is_empty() && self.password.is_empty() {
                                self.account = account.username;
                                self.password = account.password;
                                self.country = account.country;
                                self.dialing_code = account.dial_code;
                                self.keyring_message = Some(
                                    "ANRAN account restored from Linux keyring. No login was sent.",
                                );
                            } else {
                                self.keyring_message = Some("Saved ANRAN account available; existing form values were preserved.");
                            }
                        }
                        KeyringReply::Loaded(Ok(None)) => {
                            self.keyring_message =
                                Some("No saved ANRAN account found (or keyring locked). Save once to enable recall.");
                        }
                        KeyringReply::Loaded(Err(error))
                        | KeyringReply::Saved(Err(error))
                        | KeyringReply::Deleted(Err(error)) => {
                            self.keyring_message = Some(error.label());
                        }
                        KeyringReply::Saved(Ok(())) => {
                            self.keyring_message = Some(
                                "ANRAN credentials saved and verified in Linux keyring. No login was sent.",
                            );
                        }
                        KeyringReply::Deleted(Ok(())) => {
                            self.account.clear();
                            self.password.clear();
                            self.consent = false;
                            self.result = None;
                            self.keyring_message =
                                Some("Saved ANRAN account deleted from Linux keyring.");
                        }
                    }
                }
                Ok(_) => {}
                Err(TryRecvError::Empty) => self.keyring_rx = Some(rx),
                Err(TryRecvError::Disconnected) => {
                    self.keyring_message =
                        Some("Linux keyring operation stopped; no login was sent.");
                }
            }
        }
        if self.keyring_restore_pending && self.keyring_rx.is_none() && !self.busy() {
            self.start_keyring_restore();
        }
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
        self.poll_keyring();
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
        // Restore saved values after this one-shot lookup finishes, without
        // reusing consent or sending another network request.
        self.keyring_restore_pending = true;
        Some(credentials)
    }

    fn start(&mut self, saved_macs: &[Option<String>]) {
        let Some(credentials) = self.take_consented_credentials() else {
            return;
        };
        let options = DiscoveryOptions {
            inspect_platform: std::mem::take(&mut self.inspect_platform),
        };
        // Local-only selected-scope registry snapshot. It is never passed to
        // Exchange or included in its HTTP request headers or form fields.
        let mut saved_macs = saved_macs.to_vec();
        let (tx, rx) = mpsc::channel();
        self.rx = Some(rx);
        thread::spawn(move || {
            let result = meari_account::discover_account_with_options(
                &mut meari_account::HttpsExchange::default(),
                &mut meari_account::SystemClock,
                credentials,
                options,
            )
            .map(|discovery| DiscoveryReport {
                catalog: discovery.summary(),
                correlation: discovery.correlate_saved_macs(&saved_macs),
                ppcs_metadata: discovery.ppcs_metadata_summary(),
                matched_ppcs: discovery.matched_ppcs_summary(&saved_macs),
                coverage: discovery.coverage,
                diagnostic: discovery.diagnostic,
                platform: discovery.platform,
            });
            for mac in saved_macs.iter_mut().flatten() {
                mac.zeroize();
            }
            // Only aggregate counts or a fixed error code cross into the UI.
            let _ = tx.send(result);
        });
    }

    /// True only when the user explicitly requests an offline review of
    /// one saved record. Caller opens its editor; no registry change here.
    pub fn ui(
        &mut self,
        ui: &mut egui::Ui,
        saved_macs: &[Option<String>],
        can_review_saved: bool,
    ) -> bool {
        let mut review_saved_requested = false;
        egui::CollapsingHeader::new("ANRAN account discovery (experimental)")
            .default_open(false)
            .show(ui, |ui| {
                ui.label("Unofficial Meari/CloudPlus backend. Compatibility unverified.");
                ui.label(
                    "Repeated account QA has logged the phone app out after Ocularium login. Only sign in with the account owner's permission.",
                );
                ui.label(
                    "One consented login sequence: default devices, home list and up to                      8 shared-home lists. No automatic retries or automatic login.",
                );
                ui.small("Country and dialing code must match the account registration region.");
                if self.keyring_rx.is_some() || self.keyring_restore_pending {
                    ui.ctx().request_repaint_after(std::time::Duration::from_millis(100));
                }
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
                ui.small(format!(
                    "Saved cameras identified as ANRAN on this LAN: {}.                      Account lookup does not depend on this count; local MAC comparison does.",
                    saved_macs.len()
                ));
                if saved_macs.is_empty() {
                    ui.label(
                        "No saved camera is labeled as ANRAN for this network.                          This does not mean the camera is offline or that the account login failed.",
                    );
                    if can_review_saved
                        && ui
                            .button("Review saved camera identity (offline)")
                            .on_hover_text(
                                "Opens the saved camera editor below. Nothing is                                  reclassified or sent to the network automatically.",
                            )
                            .clicked()
                    {
                        review_saved_requested = true;
                    }
                }
                let keyring_busy = self.keyring_rx.is_some() || self.keyring_restore_pending;
                ui.horizontal(|ui| {
                    ui.label("Country");
                    ui.add_enabled(
                        !busy && !keyring_busy,
                        egui::TextEdit::singleline(&mut self.country).desired_width(45.0),
                    );
                    ui.label("Dial code");
                    ui.add_enabled(
                        !busy && !keyring_busy,
                        egui::TextEdit::singleline(&mut self.dialing_code).desired_width(45.0),
                    );
                });
                ui.horizontal(|ui| {
                    ui.label("Account");
                    ui.add_enabled(
                        !busy && !keyring_busy,
                        egui::TextEdit::singleline(&mut *self.account)
                            .password(true)
                            .desired_width(240.0),
                    );
                });
                ui.horizontal(|ui| {
                    ui.label("Password");
                    ui.add_enabled(
                        !busy && !keyring_busy,
                        egui::TextEdit::singleline(&mut *self.password)
                            .password(true)
                            .desired_width(240.0),
                    );
                });
                ui.horizontal(|ui| {
                    if ui.add_enabled(
                        !busy && !keyring_busy && valid(&self.account, &self.password, &self.country, &self.dialing_code),
                        egui::Button::new("Save ANRAN account to Linux keyring"),
                    ).clicked() {
                        self.save_keyring();
                    }
                    if ui.add_enabled(!busy && !keyring_busy, egui::Button::new("Forget saved ANRAN account")).clicked() {
                        self.delete_keyring();
                    }
                });
                ui.small("Save once to restore account fields next time. Requires secret-tool (libsecret) and unlocked Linux keyring; no Ocularium password files.");
                if let Some(message) = self.keyring_message {
                    ui.label(message);
                }
                ui.add_enabled_ui(!busy, |ui| {
                    ui.checkbox(
                        &mut self.inspect_platform,
                        "Also inspect optional IoT platform configuration (one extra GET)",
                    );
                });
                ui.small(
                    "Off by default. Reports only feature-presence flags; does not contact                      OpenAPI/MQTT or store any platform credentials.",
                );
                ui.add_enabled_ui(!busy, |ui| {
                    ui.checkbox(
                        &mut self.consent,
                        "I authorize this login and accept that it may sign out the phone app",
                    );
                });
                ui.horizontal(|ui| {
                    if ui
                        .add_enabled(
                            self.ready() && !keyring_busy,
                            egui::Button::new("Connect once and count devices"),
                        )
                        .clicked()
                    {
                        self.start(saved_macs);
                    }
                    if ui
                        .add_enabled(!busy && !keyring_busy, egui::Button::new("Clear form and result (keep keyring)"))
                        .clicked()
                    {
                        self.account.clear();
                        self.password.clear();
                        self.consent = false;
                        self.inspect_platform = false;
                        self.result = None;
                    }
                });
                if busy {
                    ui.spinner();
                    ui.label("Connecting once; no automatic retry.");
                }
                if let Some(result) = self.result {
                    match result {
                        Ok(report) => {
                            ui.label(report.platform.safe_text());
                            ui.label(report.coverage.safe_text());
                            if !report.coverage.default_list_ok
                                || !report.coverage.home_list_ok
                                || report.coverage.homes_attempted
                                    != report.coverage.homes_succeeded
                            {
                                ui.label(report.diagnostic.safe_partial_text());
                            }
                            ui.label(report.catalog.safe_text());
                            ui.label(report.ppcs_metadata.safe_text());
                            ui.label(report.correlation.safe_text());
                            ui.label(report.matched_ppcs.safe_text());
                            ui.small(
                                "No match is inconclusive: vendor lists often omit MACs,                                  and saved cameras may have a different app label.",
                            );
                            ui.label(
                                "PPCS and unique MAC match counts are metadata evidence only.                                  They cannot prove peer identity, connectivity or video access.",
                            );
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
        review_saved_requested
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selecting_anran_prepares_offline_restore_without_login() {
        let mut panel = AnranPanel::default();
        panel.set_paired_app(PairedApp::Anran);
        assert!(panel.keyring_restore_pending);
        assert!(!panel.consent);
        assert!(!panel.ready());
        panel.set_paired_app(PairedApp::Arcctv);
        assert!(!panel.keyring_restore_pending);
        assert!(!panel.ready());
    }

    #[test]
    fn restored_keyring_fields_never_consent_to_a_vendor_login() {
        let mut panel = AnranPanel {
            paired_app: PairedApp::Anran,
            camera_listed_in_app: true,
            ..Default::default()
        };
        let (tx, rx) = mpsc::channel();
        panel.keyring_rx = Some(rx);
        tx.send((
            panel.keyring_epoch,
            KeyringReply::Loaded(Ok(Some(KeyringAccount {
                username: Zeroizing::new("example@example.invalid".into()),
                password: Zeroizing::new("fictional-secret".into()),
                country: "US".into(),
                dial_code: "1".into(),
            }))),
        ))
        .unwrap();
        panel.poll_keyring();
        assert_eq!(panel.account.as_str(), "example@example.invalid");
        assert_eq!(panel.password.as_str(), "fictional-secret");
        assert_eq!(panel.country, "US");
        assert_eq!(panel.dialing_code, "1");
        assert!(!panel.consent);
        assert!(!panel.ready());
        assert!(panel.rx.is_none());
        assert!(panel.keyring_rx.is_none());
    }

    #[test]
    fn stale_keyring_reply_cannot_repopulate_another_app() {
        let mut panel = AnranPanel::default();
        panel.set_paired_app(PairedApp::Anran);
        panel.keyring_restore_pending = false;
        let old_epoch = panel.keyring_epoch;
        let (tx, rx) = mpsc::channel();
        panel.keyring_rx = Some(rx);
        panel.set_paired_app(PairedApp::Arcctv);
        tx.send((
            old_epoch,
            KeyringReply::Loaded(Ok(Some(KeyringAccount {
                username: Zeroizing::new("old@example.invalid".into()),
                password: Zeroizing::new("unused".into()),
                country: "US".into(),
                dial_code: "1".into(),
            }))),
        ))
        .unwrap();
        panel.poll_keyring();
        assert!(panel.account.is_empty());
        assert!(panel.password.is_empty());
        assert_eq!(panel.paired_app, PairedApp::Arcctv);
        assert!(!panel.consent);
    }

    #[test]
    fn keyring_restore_does_not_overwrite_manual_fields() {
        let mut panel = AnranPanel {
            paired_app: PairedApp::Anran,
            account: Zeroizing::new("manual@example.invalid".into()),
            password: Zeroizing::new("manual-password".into()),
            ..Default::default()
        };
        let (tx, rx) = mpsc::channel();
        panel.keyring_rx = Some(rx);
        tx.send((
            panel.keyring_epoch,
            KeyringReply::Loaded(Ok(Some(KeyringAccount {
                username: Zeroizing::new("stored@example.invalid".into()),
                password: Zeroizing::new("stored-password".into()),
                country: "US".into(),
                dial_code: "1".into(),
            }))),
        ))
        .unwrap();
        panel.poll_keyring();
        assert_eq!(panel.account.as_str(), "manual@example.invalid");
        assert_eq!(panel.password.as_str(), "manual-password");
        assert!(!panel.consent);
    }

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

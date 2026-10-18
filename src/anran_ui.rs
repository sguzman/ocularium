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

pub struct AnranPanel {
    account: Zeroizing<String>,
    password: Zeroizing<String>,
    country: String,
    dialing_code: String,
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
            && self.consent
            && valid(
                self.account.as_str(),
                self.password.as_str(),
                &self.country,
                &self.dialing_code,
            )
    }

    fn start(&mut self) {
        if !self.ready() {
            return;
        }
        let credentials = Credentials {
            account: std::mem::replace(&mut self.account, Zeroizing::new(String::new())),
            password: std::mem::replace(&mut self.password, Zeroizing::new(String::new())),
            country: self.country.clone(),
            phone_code: self.dialing_code.clone(),
        };
        self.consent = false;
        self.result = None;
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
                let busy = self.busy();
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
    fn explicit_consent_and_region_required() {
        let mut panel = AnranPanel::default();
        panel.account = Zeroizing::new("sample@example.invalid".into());
        panel.password = Zeroizing::new("sample".into());
        assert!(!panel.ready());
        panel.consent = true;
        assert!(panel.ready());
        panel.country = "mx".into();
        assert!(!panel.ready());
    }
}

//! Linux Secret Service storage for the opt-in ANRAN account form.
//! The system keyring is the sole persistent store. No shell is used.
use serde::{Deserialize, Serialize};
use std::{
    io::Write,
    process::{Command, Stdio},
};
use zeroize::{Zeroize, Zeroizing};

const LIMIT: usize = 4096;
const SELECTOR: [&str; 4] = ["application", "ocularium", "entry", "anran-v1"];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    Unavailable,
    Failed,
    Invalid,
}
impl Error {
    pub fn label(self) -> &'static str {
        match self {
            Self::Unavailable => {
                "Linux Secret Service is unavailable. Install libsecret and unlock the keyring."
            }
            Self::Failed => "The Linux keyring operation failed; no account login occurred.",
            Self::Invalid => "The saved ANRAN keyring entry is invalid and was not loaded.",
        }
    }
}

pub struct Account {
    pub username: Zeroizing<String>,
    pub password: Zeroizing<String>,
    pub country: String,
    pub dial_code: String,
}
#[derive(Serialize)]
struct Borrowed<'a> {
    username: &'a str,
    password: &'a str,
    country: &'a str,
    dial_code: &'a str,
}
#[derive(Deserialize)]
struct Owned {
    username: String,
    password: String,
    country: String,
    dial_code: String,
}
impl Drop for Owned {
    fn drop(&mut self) {
        self.username.zeroize();
        self.password.zeroize();
    }
}
impl Account {
    fn encode(&self) -> Result<Zeroizing<Vec<u8>>, Error> {
        let value = Borrowed {
            username: &self.username,
            password: &self.password,
            country: &self.country,
            dial_code: &self.dial_code,
        };
        let bytes = Zeroizing::new(serde_json::to_vec(&value).map_err(|_| Error::Invalid)?);
        if bytes.len() > LIMIT {
            return Err(Error::Invalid);
        }
        Ok(bytes)
    }
    fn decode(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.is_empty() || bytes.len() > LIMIT {
            return Err(Error::Invalid);
        }
        let mut value: Owned = serde_json::from_slice(bytes).map_err(|_| Error::Invalid)?;
        if value.username.is_empty()
            || value.username.len() > 254
            || value.password.is_empty()
            || value.password.len() > 256
            || value.country.len() != 2
            || !value.country.bytes().all(|b| b.is_ascii_uppercase())
            || !(1..=4).contains(&value.dial_code.len())
            || !value.dial_code.bytes().all(|b| b.is_ascii_digit())
        {
            return Err(Error::Invalid);
        }
        Ok(Self {
            username: Zeroizing::new(std::mem::take(&mut value.username)),
            password: Zeroizing::new(std::mem::take(&mut value.password)),
            country: value.country.clone(),
            dial_code: value.dial_code.clone(),
        })
    }
}

pub fn save(value: Account) -> Result<(), Error> {
    let payload = value.encode()?;
    let mut cmd = Command::new("secret-tool");
    cmd.args(["store", "--label=Ocularium ANRAN account"])
        .args(SELECTOR)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let mut child = cmd.spawn().map_err(|_| Error::Unavailable)?;
    let sent = child
        .stdin
        .take()
        .is_some_and(|mut stream| stream.write_all(&payload).is_ok());
    let success = child.wait().map_err(|_| Error::Failed)?.success();
    if sent && success {
        Ok(())
    } else {
        Err(Error::Failed)
    }
}
fn command(action: &'static str) -> Command {
    let mut cmd = Command::new("secret-tool");
    cmd.arg(action)
        .args(SELECTOR)
        .stdin(Stdio::null())
        .stderr(Stdio::null());
    cmd
}
pub fn load() -> Result<Option<Account>, Error> {
    let output = command("lookup")
        .stdout(Stdio::piped())
        .output()
        .map_err(|_| Error::Unavailable)?;
    let secret = Zeroizing::new(output.stdout);
    if !output.status.success() {
        // secret-tool lookup exits 1 when an entry is absent, as well as
        // some keyring failures. Neither case implies invalid credentials.
        if output.status.code() == Some(1) && secret.is_empty() {
            return Ok(None);
        }
        return Err(Error::Failed);
    }
    if secret.is_empty() {
        return Ok(None);
    }
    Account::decode(&secret).map(Some)
}
pub fn delete() -> Result<(), Error> {
    let exit = command("clear")
        .stdout(Stdio::null())
        .status()
        .map_err(|_| Error::Unavailable)?;
    if exit.success() {
        Ok(())
    } else {
        Err(Error::Failed)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn roundtrip_is_bounded_and_contains_no_real_account_data() {
        let item = Account {
            username: Zeroizing::new("fixture@example.invalid".into()),
            password: Zeroizing::new("example-pass".into()),
            country: "US".into(),
            dial_code: "1".into(),
        };
        let payload = item.encode().unwrap();
        let restored = Account::decode(&payload).unwrap();
        assert_eq!(&*restored.username, "fixture@example.invalid");
        assert_eq!(&*restored.password, "example-pass");
        assert!(matches!(
            Account::decode(&vec![0; LIMIT + 1]),
            Err(Error::Invalid)
        ));
    }
    #[test]
    fn incorrect_regions_are_rejected() {
        let value = br#"{"username":"a","password":"b","country":"mx","dial_code":"52"}"#;
        assert!(matches!(Account::decode(value), Err(Error::Invalid)));
    }
}

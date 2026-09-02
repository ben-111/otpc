mod tui;

use anyhow::{Context, Result};
use google_authenticator_converter::{self, Account};
use keyring::{Entry, Error as KeyringError};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use totp_rs::Totp;

const KEYRING_SERVICE: &str = "otpc";
const KEYRING_USER: &str = "totp-secrets";
const FIRST_CREDENTIAL_ID: u64 = 1;

#[derive(Clone, Deserialize, Serialize)]
struct Credential {
    id: u64,
    issuer: String,
    name: String,
    url: String,
}

#[derive(Clone, Deserialize, Serialize)]
struct Config {
    next_id: u64,
    credentials: Vec<Credential>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            next_id: FIRST_CREDENTIAL_ID,
            credentials: Vec::new(),
        }
    }
}

#[derive(Clone)]
struct NewCredential {
    issuer: String,
    name: String,
    url: String,
}

impl Config {
    fn add(&mut self, credentials: Vec<NewCredential>) -> Result<usize> {
        if credentials.is_empty() {
            anyhow::bail!("No credentials found");
        }

        let count = credentials.len();
        let next_id = self
            .next_id
            .checked_add(count as u64)
            .context("Credential ID limit reached")?;

        for (offset, credential) in credentials.into_iter().enumerate() {
            self.credentials.push(Credential {
                id: self.next_id + offset as u64,
                issuer: credential.issuer,
                name: credential.name,
                url: credential.url,
            });
        }
        self.next_id = next_id;
        Ok(count)
    }
}

fn read_config(entry: &Entry) -> Result<Config> {
    match entry.get_secret() {
        Ok(raw_config) => {
            serde_json::from_slice(&raw_config).context("Failed to parse config from keyring")
        }
        Err(KeyringError::NoEntry) => Ok(Config::default()),
        Err(error) => Err(error).context("Failed to read config from keyring"),
    }
}

fn write_config(entry: &Entry, config: &Config) -> Result<()> {
    let raw_config = serde_json::to_vec(config).context("Failed to serialize config")?;
    entry
        .set_secret(&raw_config)
        .context("Failed to save config to keyring")
}

fn account_to_otpauth_url(account: &Account) -> String {
    let issuer = urlencoding::encode(&account.issuer);
    let name = urlencoding::encode(&account.name);
    format!(
        "otpauth://totp/{}:{}?secret={}&issuer={}",
        issuer, name, account.secret, issuer
    )
}

fn credentials_from_url(url: &str) -> Result<Vec<NewCredential>> {
    if url.starts_with("otpauth-migration://") {
        let accounts = google_authenticator_converter::process_data(url)
            .map_err(|_| anyhow::anyhow!("Error parsing otpauth-migration URL"))?;

        return accounts
            .into_iter()
            .map(|account| {
                if account.issuer.is_empty() {
                    anyhow::bail!("TOTP account is missing an issuer");
                }
                let url = account_to_otpauth_url(&account);
                Ok(NewCredential {
                    issuer: account.issuer,
                    name: account.name,
                    url,
                })
            })
            .collect();
    }

    let totp = Totp::from_url_unchecked(url).context("Error parsing otpauth URL")?;
    let issuer = totp
        .issuer()
        .context("TOTP URL is missing an issuer")?
        .to_owned();
    if totp.account_name().is_empty() {
        anyhow::bail!("TOTP URL is missing an account name");
    }

    Ok(vec![NewCredential {
        issuer,
        name: totp.account_name().to_owned(),
        url: url.to_owned(),
    }])
}

fn url_from_qr_image(path: &Path) -> Result<String> {
    let path_string = path
        .to_str()
        .with_context(|| format!("Image path is not valid UTF-8: {}", path.display()))?;
    let result =
        rxing::helpers::detect_in_file(path_string, Some(rxing::BarcodeFormat::QR_CODE))
            .with_context(|| format!("Failed to decode QR code in image {}", path.display()))?;

    Ok(result.getText().trim().to_owned())
}

fn expand_home(path: &Path) -> Result<PathBuf> {
    if path.strip_prefix("~").is_err() {
        return Ok(path.to_owned());
    }
    let home = homedir::my_home()
        .context("Failed to determine home directory")?
        .context("Home directory not found")?;
    Ok(expand_home_from(path, &home))
}

fn expand_home_from(path: &Path, home: &Path) -> PathBuf {
    path.strip_prefix("~")
        .map(|suffix| home.join(suffix))
        .unwrap_or_else(|_| path.to_owned())
}

fn credentials_from_source(source: &str) -> Result<Vec<NewCredential>> {
    let url = if source.starts_with("otpauth://") || source.starts_with("otpauth-migration://") {
        source.to_owned()
    } else {
        url_from_qr_image(&expand_home(Path::new(source))?)?
    };

    credentials_from_url(&url)
}

fn credentials_from_screenshot() -> Result<Vec<NewCredential>> {
    let monitors = xcap::Monitor::all().context("Failed to enumerate displays")?;
    if monitors.is_empty() {
        anyhow::bail!("No displays found");
    }

    let mut invalid_payload = None;
    for monitor in monitors {
        let screenshot = monitor
            .capture_image()
            .context("Failed to capture display; screen-recording permission may be required")?;
        let screenshot = xcap::image::DynamicImage::ImageRgba8(screenshot);
        let Ok(result) =
            rxing::helpers::detect_in_image(screenshot, Some(rxing::BarcodeFormat::QR_CODE))
        else {
            continue;
        };

        match credentials_from_url(result.getText().trim()) {
            Ok(credentials) => return Ok(credentials),
            Err(error) => invalid_payload = Some(error),
        }
    }

    match invalid_payload {
        Some(error) => Err(error).context("Screen QR code does not contain a valid OTP URL"),
        None => anyhow::bail!("No QR code found on any display"),
    }
}

fn main() -> Result<()> {
    let entry =
        Entry::new(KEYRING_SERVICE, KEYRING_USER).context("Failed to initialize keyring entry")?;
    let config = read_config(&entry)?;
    tui::run(&entry, config)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_an_otpauth_credential() {
        let url = "otpauth://totp/GitHub:user%40example.com?secret=KRSXG5CTMVRXEZLUKN2XAZLSKNSWG4TFOQ&issuer=GitHub";
        let credentials = credentials_from_url(url).unwrap();

        assert_eq!(credentials.len(), 1);
        assert_eq!(credentials[0].issuer, "GitHub");
        assert_eq!(credentials[0].name, "user@example.com");
        assert_eq!(credentials[0].url, url);
    }

    #[test]
    fn deleted_ids_are_not_reused() {
        let mut config = Config {
            next_id: 4,
            credentials: Vec::new(),
        };

        config
            .add(vec![NewCredential {
                issuer: "Example".to_owned(),
                name: "alice".to_owned(),
                url: "url".to_owned(),
            }])
            .unwrap();

        assert_eq!(config.credentials[0].id, 4);
        assert_eq!(config.next_id, 5);
    }

    #[test]
    fn expands_a_leading_tilde_path_component() {
        let home = Path::new("/Users/test");

        assert_eq!(
            expand_home_from(Path::new("~/Downloads/authenticator.png"), home),
            Path::new("/Users/test/Downloads/authenticator.png")
        );
        assert_eq!(
            expand_home_from(Path::new("~other/authenticator.png"), home),
            Path::new("~other/authenticator.png")
        );
    }
}

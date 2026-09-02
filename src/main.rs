mod tui;

use anyhow::{Context, Result};
use google_authenticator_converter::{self, Account};
use keyring::{Entry, Error as KeyringError};
use serde::{Deserialize, Serialize};
use std::path::Path;
use totp_rs::TOTP;

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

    let totp = TOTP::from_url_unchecked(url).context("Error parsing otpauth URL")?;
    let issuer = totp.issuer.context("TOTP URL is missing an issuer")?;
    if totp.account_name.is_empty() {
        anyhow::bail!("TOTP URL is missing an account name");
    }

    Ok(vec![NewCredential {
        issuer,
        name: totp.account_name,
        url: url.to_owned(),
    }])
}

fn url_from_qr_image(path: &Path) -> Result<String> {
    let image = image::open(path)
        .with_context(|| format!("Failed to open QR code image {}", path.display()))?
        .into_luma8();
    let mut image = rqrr::PreparedImage::prepare(image);
    let grid = image
        .detect_grids()
        .into_iter()
        .next()
        .with_context(|| format!("No QR code found in image {}", path.display()))?;
    let (_, content) = grid
        .decode()
        .with_context(|| format!("Failed to decode QR code in image {}", path.display()))?;

    Ok(content.trim().to_owned())
}

fn credentials_from_source(source: &str) -> Result<Vec<NewCredential>> {
    let url = if source.starts_with("otpauth://") || source.starts_with("otpauth-migration://") {
        source.to_owned()
    } else {
        url_from_qr_image(Path::new(source))?
    };

    credentials_from_url(&url)
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
}

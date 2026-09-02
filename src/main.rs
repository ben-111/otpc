use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use google_authenticator_converter::{self, Account};
use itertools::Itertools;
use keyring::{Entry, Error as KeyringError};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io::{self, Write};
use std::path::Path;
use std::time;
use totp_rs::TOTP;

const KEYRING_SERVICE: &str = "otpc";
const KEYRING_USER: &str = "totp-secrets";

/// Simple TOTP client
#[derive(Parser)]
#[command(version, about, long_about = None)]
#[command(propagate_version = true)]
struct Args {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Add TOTP secrets from a URL or QR code image
    Add {
        /// An otpauth URL, otpauth-migration URL, or QR code image path
        source: String,
    },

    /// List all TOTP secrets
    List,

    /// Get the current TOTP value of a secret
    Get {
        /// Name of the TOTP secret
        name: String,
    },

    /// Delete TOTP secret
    Delete {
        /// Name of the TOTP secret
        name: String,
    },
}

#[derive(Default, Deserialize, Serialize)]
struct Config {
    secrets: HashMap<String, String>,
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

fn add_otpauth_to_config(config: &mut Config, name: &str, secret: &str) {
    config.secrets.insert(name.to_owned(), secret.to_owned());
}

fn add_secret(config: &mut Config, name: &str, secret: &str) -> Result<bool> {
    if config.secrets.contains_key(name) {
        let overwrite = dialoguer::Confirm::new()
            .with_prompt("A secret exists with that name. Overwrite?")
            .interact()
            .context("Failed to read confirmation")?;
        if !overwrite {
            return Ok(false);
        }
    }

    add_otpauth_to_config(config, name, secret);
    Ok(true)
}

fn secrets_from_url(url: &str) -> Result<Vec<(String, String)>> {
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
                Ok((account.issuer, url))
            })
            .collect();
    }

    let totp = TOTP::from_url_unchecked(url).context("Error parsing otpauth URL")?;
    let issuer = totp.issuer.context("TOTP URL is missing an issuer")?;
    Ok(vec![(issuer, url.to_owned())])
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

fn secrets_from_source(source: &str) -> Result<Vec<(String, String)>> {
    let url = if source.starts_with("otpauth://") || source.starts_with("otpauth-migration://") {
        source.to_owned()
    } else {
        url_from_qr_image(Path::new(source))?
    };

    secrets_from_url(&url)
}

fn add_from_source(config: &mut Config, source: &str) -> Result<bool> {
    let mut config_changed = false;

    for (issuer, secret) in secrets_from_source(source)? {
        config_changed |= add_secret(config, &issuer, &secret)?;
    }

    Ok(config_changed)
}

fn list_secrets(config: &Config) {
    config
        .secrets
        .keys()
        .sorted()
        .for_each(|name| println!("{}", name));
}

fn get_totp(config: &Config, name: &str) -> Result<()> {
    let secret = config.secrets.get(name).context("Secret not found")?;
    let totp = TOTP::from_url_unchecked(secret).context("Error generating TOTP code")?;

    loop {
        print!(
            "\x1b[2K\r{} TTL: {}",
            totp.generate_current()
                .context("Failed to generate TOTP code")?,
            totp.ttl().context("Failed to calculate TOTP TTL")?
        );
        io::stdout().flush().context("Failed to write TOTP code")?;
        std::thread::sleep(time::Duration::from_secs(1));
    }
}

fn account_to_otpauth_url(account: &Account) -> String {
    format!(
        "otpauth://totp/{}?secret={}&issuer={}",
        account.name, account.secret, account.issuer
    )
}

fn delete_secret(config: &mut Config, name: &str) -> Result<()> {
    config.secrets.remove(name).context("Secret not found")?;
    Ok(())
}

fn main() -> Result<()> {
    let args = Args::parse();
    let entry =
        Entry::new(KEYRING_SERVICE, KEYRING_USER).context("Failed to initialize keyring entry")?;
    let mut config = read_config(&entry)?;

    let config_changed = match &args.command {
        Commands::Add { source } => add_from_source(&mut config, source)?,
        Commands::List => {
            list_secrets(&config);
            false
        }
        Commands::Get { name } => return get_totp(&config, name),
        Commands::Delete { name } => {
            delete_secret(&mut config, name)?;
            true
        }
    };

    if config_changed {
        write_config(&entry, &config)?;
    }

    Ok(())
}

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use google_authenticator_converter::{self, Account};
use itertools::Itertools;
use keyring::{Entry, Error as KeyringError};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io::{self, Write};
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
    /// Add a TOTP secret
    Add {
        /// Name of the TOTP secret
        name: String,

        /// The secret as an otpauth URL
        secret: String,
    },

    /// List all TOTP secrets
    List,

    /// Get the current TOTP value of a secret
    Get {
        /// Name of the TOTP secret
        name: String,
    },

    /// Import TOTP secrets from Google Authenticator
    Import {
        /// otpauth-migration URL
        url: String,
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

fn import_from_google_auth(config: &mut Config, migration_url: &str) -> Result<()> {
    let accounts = google_authenticator_converter::process_data(migration_url)
        .map_err(|_| anyhow::anyhow!("Error parsing migration URL"))?;

    for account in accounts {
        let secret = account_to_otpauth_url(&account);
        add_otpauth_to_config(config, &account.issuer, &secret);
    }

    Ok(())
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
        Commands::Add { name, secret } => add_secret(&mut config, name, secret)?,
        Commands::List => {
            list_secrets(&config);
            false
        }
        Commands::Get { name } => return get_totp(&config, name),
        Commands::Import { url } => {
            import_from_google_auth(&mut config, url)?;
            true
        }
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

use base64::{engine::general_purpose, Engine as _};
use clap::{Parser, Subcommand};
use dialoguer;
use google_authenticator_converter::{self, Account};
use homedir;
use serde::{Deserialize, Serialize};
use serde_json;
use simple_crypt::{decrypt, encrypt};
use totp_rs::TOTP;

use std::{collections::HashMap, error::Error, path::PathBuf};

use std::fmt;

#[derive(Debug)]
struct OTPCError {
    details: String,
}

impl OTPCError {
    fn new(msg: &str) -> OTPCError {
        OTPCError {
            details: msg.to_string(),
        }
    }
}

impl fmt::Display for OTPCError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.details)
    }
}

impl Error for OTPCError {
    fn description(&self) -> &str {
        &self.details
    }
}

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
}

#[derive(Deserialize, Serialize)]
struct Config {
    secrets: HashMap<String, String>,
}

fn get_config_path() -> PathBuf {
    let homedir = homedir::get_my_home().unwrap().unwrap();
    let appdir = homedir.as_path().join(".otpc");
    if std::fs::metadata(&appdir).is_err() {
        std::fs::create_dir(&appdir).expect("Failed creating .otpc directory: {}");
    }

    let config_path = appdir.join("config.json");

    return config_path;
}

fn read_config() -> Config {
    let config_file = get_config_path();
    if std::fs::metadata(&config_file).is_err() {
        return Config {
            secrets: HashMap::new(),
        };
    }

    let config: Config =
        serde_json::from_reader(std::fs::File::open(&config_file).unwrap()).unwrap();
    return config;
}

fn write_config(config: &Config) {
    let config_file = get_config_path();
    serde_json::to_writer(std::fs::File::create(config_file).unwrap(), config).unwrap();
}

fn get_password() -> String {
    return dialoguer::Password::new()
        .with_prompt("Enter password")
        .interact()
        .unwrap();
}

fn add_otpauth_to_config(config: &mut Config, name: &String, secret: &String, password: &String) {
    let encrypted_bytes = encrypt(secret.as_bytes(), password.as_bytes()).unwrap();
    let encoded_secret = general_purpose::STANDARD.encode(&encrypted_bytes);

    config.secrets.insert(name.clone(), encoded_secret);
}

fn add_secret(config: &mut Config, name: &String, secret: &String) -> Result<(), OTPCError> {
    println!("Adding secret {:?} to entry {}", secret, name);
    if config.secrets.contains_key(name) {
        let overwrite = dialoguer::Confirm::new()
            .with_prompt("A secret exists with that name. Overwrite?")
            .interact()
            .unwrap();
        if !overwrite {
            return Ok(());
        }
    }
    let password = get_password();
    add_otpauth_to_config(config, name, secret, &password);
    write_config(&config);
    Ok(())
}

fn list_secrets(config: &Config) -> Result<(), OTPCError> {
    config.secrets.keys().for_each(|name| println!("{}", name));
    Ok(())
}

fn get_totp(config: &Config, name: &String) -> Result<(), OTPCError> {
    match config.secrets.get(name) {
        Some(secret) => {
            let decoded = general_purpose::STANDARD.decode(&secret).unwrap();
            let password = get_password();
            match decrypt(&decoded, password.as_bytes()) {
                Ok(decrypted) => {
                    let secret = String::from_utf8(decrypted).unwrap();

                    match TOTP::from_url(secret) {
                        Ok(totp) => {
                            println!(
                                "{} TTL: {}",
                                totp.generate_current().unwrap(),
                                totp.ttl().unwrap()
                            );
                            return Ok(());
                        }
                        Err(e) => {
                            return Err(OTPCError::new(&format!(
                                "Error generating TOTP code: {}",
                                e.to_string(),
                            )))
                        }
                    }
                }
                Err(_) => return Err(OTPCError::new("Wrong password")),
            }
        }
        None => {
            return Err(OTPCError::new("Secret not found"));
        }
    }
}

fn account_to_otpauth_url(account: &Account) -> String {
    return format!(
        "otpauth://totp/{}?secret={}&issuer={}",
        account.name, account.secret, account.issuer
    );
}

fn import_from_google_auth(config: &mut Config, migration_url: &String) -> Result<(), OTPCError> {
    match google_authenticator_converter::process_data(&migration_url) {
        Ok(accounts) => {
            let password = get_password();
            for account in accounts {
                let secret = account_to_otpauth_url(&account);
                println!("{}", secret);
                add_otpauth_to_config(config, &account.issuer, &secret, &password);
            }

            write_config(config);
            Ok(())
        }
        Err(_) => Err(OTPCError::new("Error parsing migration URL")),
    }
}

fn main() -> Result<(), OTPCError> {
    let args = Args::parse();

    let mut config = read_config();

    match &args.command {
        Commands::Add { name, secret } => return add_secret(&mut config, name, secret),
        Commands::List => return list_secrets(&config),
        Commands::Get { name } => return get_totp(&config, &name),
        Commands::Import { url } => return import_from_google_auth(&mut config, url),
    }
}

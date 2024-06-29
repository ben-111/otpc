use clap::{Parser, Subcommand};
use homedir;
use serde::{Deserialize, Serialize};
use serde_json;

use std::{collections::HashMap, path::PathBuf};

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
    /// Add a TOTP secret with a name
    Add {
        /// Name of the TOTP secret
        name: String,

        /// The secret encoded in base32 or as an otpauth URL
        secret: String,
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
        std::fs::create_dir(&appdir).expect("Failed creating .otpc directory");
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

fn main() {
    let args = Args::parse();

    let mut config = read_config();

    match &args.command {
        Commands::Add { name, secret } => {
            println!("Adding secret {:?} to entry {}", secret, name);
            config.secrets.insert(name.clone(), secret.clone());
            write_config(&config);
        }
    }
}

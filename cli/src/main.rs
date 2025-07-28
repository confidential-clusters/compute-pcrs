use std::result::Result::Ok;

use anyhow::Result;
use clap::{Parser, Subcommand};
use log::LevelFilter;
use serde::{Deserialize, Serialize};

use compute_pcrs_lib::*;

#[derive(Parser, Debug)]
#[command(
    version,
    about,
    long_about = "Pre-compute PCR values for Bootable Container systems"
)]
struct Cli {
    /// Log verbosity. Defaults to Warn, -v for Info, -vv for Debug, -vvv for Trace
    #[arg(short = 'v', long, action = clap::ArgAction::Count, global = true)]
    verbose: u8,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    // Compute all possible PCR values
    All {
        #[arg(
            long,
            default_value_t = false,
            help = "Indicates that the linux image is an UKI image (e.g. is not vmlinuz))"
        )]
        uki: bool,
    },
    /// Compute PCR 4
    Pcr4 {
        #[arg(
            long,
            default_value_t = false,
            help = "Indicates that the linux image is an UKI image (e.g. is not vmlinuz))"
        )]
        uki: bool,
    },
    /// Compute PCR 7
    Pcr7 {},
    /// Compute PCR 11
    Pcr11 {},
}

#[derive(Serialize, Deserialize)]
struct Output {
    pcrs: Vec<Pcr>,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    let level = match cli.verbose {
        0 => LevelFilter::Warn,
        1 => LevelFilter::Info,
        2 => LevelFilter::Debug,
        _ => LevelFilter::Trace,
    };

    env_logger::Builder::new()
        .filter(None, level)
        .format_timestamp(None)
        .init();

    match &cli.command {
        Command::All { uki } => {
            let pcrs = vec![compute_pcr4(*uki), compute_pcr7(), compute_pcr11()];
            println!(
                "{}",
                serde_json::to_string_pretty(&Output { pcrs }).unwrap()
            );
            Ok(())
        }
        Command::Pcr4 { uki } => {
            let pcr = compute_pcr4(*uki);
            println!("{}", serde_json::to_string_pretty(&pcr).unwrap());
            Ok(())
        }
        Command::Pcr7 {} => {
            let pcr = compute_pcr7();
            println!("{}", serde_json::to_string_pretty(&pcr).unwrap());
            Ok(())
        }
        Command::Pcr11 {} => {
            let pcr = compute_pcr11();
            println!("{}", serde_json::to_string_pretty(&pcr).unwrap());
            Ok(())
        }
    }
}

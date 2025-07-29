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
    /// Compute all possible PCR values from the binaries available in the current environment. Meant to be run inside a Bootable Container.
    All {
        #[arg(
            long,
            short,
            default_value = "/usr/lib/modules/",
            help = "Path to the kernel modules directory. This helps finding the vmlinuz image"
        )]
        kernels: String,
        #[arg(
            long,
            short,
            default_value = "/usr/lib/bootupd/updates/",
            help = "Path to the ESP directory"
        )]
        esp: String,
        #[arg(
            long,
            default_value_t = false,
            help = "Indicates that the linux image is an UKI image (e.g. is not vmlinuz))"
        )]
        uki: bool,
        #[arg(
            long = "secureboot-disabled",
            default_value_t = false,
            help = "Compute PCRs as if secure boot was disabled in the system"
        )]
        no_secureboot: bool,
    },
    /// Compute PCR 4
    Pcr4 {
        #[arg(
            long,
            short,
            default_value = "/usr/lib/modules/",
            help = "Path to the kernel modules directory. This helps finding the vmlinuz image"
        )]
        kernels: String,
        #[arg(
            long,
            short,
            default_value = "/usr/lib/bootupd/updates/",
            help = "Path to the ESP directory"
        )]
        esp: String,
        #[arg(
            long,
            default_value_t = false,
            help = "Indicates that the linux image is an UKI image (e.g. is not vmlinuz))"
        )]
        uki: bool,
        #[arg(
            long = "secureboot-disabled",
            default_value_t = false,
            help = "Compute PCRs as if secure boot was disabled in the system"
        )]
        no_secureboot: bool,
    },
    /// Compute PCR 7
    Pcr7 {},
    /// Compute PCR 11
    Pcr11 {
        /// Path to a UKI
        uki: String,
    },
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
        Command::All {
            kernels,
            esp,
            uki,
            no_secureboot,
        } => {
            let pcrs = vec![
                compute_pcr4(kernels, esp, *uki, !no_secureboot),
                /* compute_pcr7(), */
                /* compute_pcr11(), */
            ];
            println!(
                "{}",
                serde_json::to_string_pretty(&Output { pcrs }).unwrap()
            );
            Ok(())
        }
        Command::Pcr4 {
            kernels,
            esp,
            uki,
            no_secureboot,
        } => {
            let pcr = compute_pcr4(kernels, esp, *uki, !no_secureboot);
            println!("{}", serde_json::to_string_pretty(&pcr).unwrap());
            Ok(())
        }
        Command::Pcr7 {} => {
            let pcr = compute_pcr7();
            println!("{}", serde_json::to_string_pretty(&pcr).unwrap());
            Ok(())
        }
        Command::Pcr11 { uki } => {
            let pcr = compute_pcr11(uki);
            println!("{}", serde_json::to_string_pretty(&pcr).unwrap());
            Ok(())
        }
    }
}

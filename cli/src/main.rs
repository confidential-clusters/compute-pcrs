// SPDX-FileCopyrightText: Timothée Ravier <tim@siosm.fr>
// SPDX-FileCopyrightText: Beñat Gartzia Arruabarrena <bgartzia@redhat.com>
//
// SPDX-License-Identifier: MIT

use std::result::Result::Ok;

use anyhow::Result;
use clap::{Args, Parser, Subcommand};
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

#[derive(Args, Debug)]
#[group(required = true, multiple = false)]
struct SecureBootVarStores {
    #[arg(long, help = "Path to the directory storing EFIVar files")]
    efivars: Option<String>,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Compute all possible PCR values from the binaries available in the current environment. Meant to be run inside a Bootable Container.
    All {
        #[arg(
            long,
            short,
            default_value = "/",
            help = "Path to the target container image root filesystem"
        )]
        rootfs: String,
        #[command(flatten)]
        secureboot_variables: SecureBootVarStores,
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
        #[arg(
            long = "mok-variables",
            required = true,
            help = "Path to directory storing MokListRT, MokListTrustedRT and MokListXRT"
        )]
        mok_variables: String,
    },
    /// Compute PCR 4
    Pcr4 {
        #[arg(
            long,
            short,
            default_value = "/",
            help = "Path to the target container image root filesystem"
        )]
        rootfs: String,
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
    Pcr7 {
        #[arg(
            long,
            short,
            default_value = "/",
            help = "Path to the target container image root filesystem"
        )]
        rootfs: String,
        #[command(flatten)]
        secureboot_variables: SecureBootVarStores,
        #[arg(
            long = "secureboot-disabled",
            default_value_t = false,
            help = "Compute PCRs as if secure boot was disabled in the system"
        )]
        no_secureboot: bool,
    },
    /// Compute PCR 11
    Pcr11 {
        /// Path to a UKI
        uki: String,
    },
    /// Compute PCR 14
    Pcr14 {
        #[arg(
            long = "mok-variables",
            required = true,
            help = "Path to directory storing MokListRT, MokListTrustedRT and MokListXRT"
        )]
        mok_variables: String,
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
            rootfs,
            secureboot_variables,
            uki,
            no_secureboot,
            mok_variables,
        } => {
            let rfs = rootfs::RootFSTree::new(rootfs).unwrap();
            let pcrs = vec![
                compute_pcr4(rfs.vmlinuz(), rfs.esp(), *uki, !no_secureboot),
                compute_pcr7(
                    secureboot_variables.efivars.as_deref(),
                    rfs.esp(),
                    !no_secureboot,
                ),
                /* compute_pcr11(), */
                compute_pcr14(mok_variables),
            ];
            println!(
                "{}",
                serde_json::to_string_pretty(&Output { pcrs }).unwrap()
            );
            Ok(())
        }
        Command::Pcr4 {
            rootfs,
            uki,
            no_secureboot,
        } => {
            let rfs = rootfs::RootFSTree::new(rootfs).unwrap();
            let pcr = compute_pcr4(rfs.vmlinuz(), rfs.esp(), *uki, !no_secureboot);
            println!("{}", serde_json::to_string_pretty(&pcr).unwrap());
            Ok(())
        }
        Command::Pcr7 {
            rootfs,
            secureboot_variables,
            no_secureboot,
        } => {
            let rfs = rootfs::RootFSTree::new(rootfs).unwrap();
            let pcr = compute_pcr7(
                secureboot_variables.efivars.as_deref(),
                rfs.esp(),
                !no_secureboot,
            );
            println!("{}", serde_json::to_string_pretty(&pcr).unwrap());
            Ok(())
        }
        Command::Pcr11 { uki } => {
            let pcr = compute_pcr11(uki);
            println!("{}", serde_json::to_string_pretty(&pcr).unwrap());
            Ok(())
        }
        Command::Pcr14 { mok_variables } => {
            let pcr = compute_pcr14(mok_variables);
            println!("{}", serde_json::to_string_pretty(&pcr).unwrap());
            Ok(())
        }
    }
}

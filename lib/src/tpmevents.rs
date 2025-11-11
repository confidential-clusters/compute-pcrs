// SPDX-FileCopyrightText: Beñat Gartzia Arruabarrena <bgartzia@redhat.com>
//
// SPDX-License-Identifier: MIT
use serde::{Deserialize, Serialize};
use serde_with::serde_as;

pub mod compute;
mod tree;

// Event group definitions
pub const TPMEG_EMPTY: u32 = 0; // Empty to extend/compare
pub const TPMEG_NEVER: u32 = 0; // No group, never changes
pub const TPMEG_LINUX: u32 = 1 << 1; // Events depending on vmlinuz
pub const TPMEG_BOOTLOADER: u32 = 1 << 2; // Events depending on shim or grub
pub const TPMEG_SECUREBOOT: u32 = 1 << 3; // Events depending on secure boot variables
pub const TPMEG_MOKVARS: u32 = 1 << 4; // Events depending on MOK variables
pub const TPMEG_UKI: u32 = 1 << 5; // Events depending on UKI
pub const TPMEG_ALWAYS: u32 = u32::MAX; // Events that always change

#[derive(Clone, Serialize, Deserialize, Hash, PartialEq, Eq)]
pub enum TPMEventID {
    Pcr4EfiCall,
    Pcr4Separator,
    Pcr4Shim,
    Pcr4Grub,
    Pcr4Vmlinuz,
    Pcr7SecureBoot,
    Pcr7Pk,
    Pcr7Kek,
    Pcr7Db,
    Pcr7Dbx,
    Pcr7Separator,
    Pcr7ShimCert,
    Pcr7SbatLevel,
    Pcr7GrubDbCert,
    Pcr7GrubVendorDbCert,
    Pcr7GrubMokListCert,
    Pcr11Linux,
    Pcr11LinuxContent,
    Pcr11Osrel,
    Pcr11OsrelContent,
    Pcr11Cmdline,
    Pcr11CmdlineContent,
    Pcr11Initrd,
    Pcr11InitrdContent,
    Pcr11Uname,
    Pcr11UnameContent,
    Pcr11Sbat,
    Pcr11SbatContent,
    Pcr14MokList,
    Pcr14MokListX,
    Pcr14MokListTrusted,
}

impl TPMEventID {
    pub fn groups(&self) -> u32 {
        match *self {
            TPMEventID::Pcr4EfiCall => TPMEG_NEVER,
            TPMEventID::Pcr4Separator => TPMEG_NEVER,
            TPMEventID::Pcr4Shim => TPMEG_BOOTLOADER,
            TPMEventID::Pcr4Grub => TPMEG_BOOTLOADER,
            TPMEventID::Pcr4Vmlinuz => TPMEG_LINUX,
            TPMEventID::Pcr7SecureBoot => TPMEG_SECUREBOOT,
            TPMEventID::Pcr7Pk => TPMEG_SECUREBOOT,
            TPMEventID::Pcr7Kek => TPMEG_SECUREBOOT,
            TPMEventID::Pcr7Db => TPMEG_SECUREBOOT,
            TPMEventID::Pcr7Dbx => TPMEG_SECUREBOOT,
            TPMEventID::Pcr7Separator => TPMEG_NEVER,
            TPMEventID::Pcr7ShimCert => TPMEG_SECUREBOOT | TPMEG_BOOTLOADER,
            // Secure boot on/off also changes the logged sbatlevel
            TPMEventID::Pcr7SbatLevel => TPMEG_SECUREBOOT | TPMEG_BOOTLOADER,
            TPMEventID::Pcr7GrubDbCert => TPMEG_SECUREBOOT | TPMEG_BOOTLOADER,
            TPMEventID::Pcr7GrubVendorDbCert => TPMEG_SECUREBOOT | TPMEG_BOOTLOADER,
            TPMEventID::Pcr7GrubMokListCert => TPMEG_SECUREBOOT | TPMEG_BOOTLOADER | TPMEG_MOKVARS,
            TPMEventID::Pcr11Linux => TPMEG_UKI,
            TPMEventID::Pcr11LinuxContent => TPMEG_UKI,
            TPMEventID::Pcr11Osrel => TPMEG_UKI,
            TPMEventID::Pcr11OsrelContent => TPMEG_UKI,
            TPMEventID::Pcr11Cmdline => TPMEG_UKI,
            TPMEventID::Pcr11CmdlineContent => TPMEG_UKI,
            TPMEventID::Pcr11Initrd => TPMEG_UKI,
            TPMEventID::Pcr11InitrdContent => TPMEG_UKI,
            TPMEventID::Pcr11Uname => TPMEG_UKI,
            TPMEventID::Pcr11UnameContent => TPMEG_UKI,
            TPMEventID::Pcr11Sbat => TPMEG_UKI,
            TPMEventID::Pcr11SbatContent => TPMEG_UKI,
            TPMEventID::Pcr14MokList => TPMEG_MOKVARS,
            TPMEventID::Pcr14MokListX => TPMEG_MOKVARS,
            TPMEventID::Pcr14MokListTrusted => TPMEG_MOKVARS,
        }
    }
}

#[serde_as]
#[derive(Clone, Serialize, Deserialize, PartialEq, Debug)]
pub struct TPMEvent {
    pub name: String,
    pub pcr: u8,
    #[serde_as(as = "serde_with::hex::Hex")]
    pub hash: Vec<u8>,
    pub id: TPMEventID,
}

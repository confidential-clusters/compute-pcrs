// SPDX-FileCopyrightText: Beñat Gartzia Arruabarrena <bgartzia@redhat.com>
//
// SPDX-License-Identifier: MIT
use serde::{Deserialize, Serialize};
use serde_with::serde_as;

pub mod compute;

// Event group definitions
pub const TPMEG_EMPTY: u32 = 0; // Empty to extend/compare
pub const TPMEG_NEVER: u32 = 0; // No group, never changes
pub const TPMEG_LINUX: u32 = 1 << 1; // Events depending on vmlinuz
pub const TPMEG_BOOTLOADER: u32 = 1 << 2; // Events depending on shim or grub
pub const TPMEG_SECUREBOOT: u32 = 1 << 3; // Events depending on secure boot variables
pub const TPMEG_MOKVARS: u32 = 1 << 4; // Events depending on MOK variables
pub const TPMEG_UKI: u32 = 1 << 5; // Events depending on UKI
pub const TPMEG_ALWAYS: u32 = u32::MAX; // Events that always change

#[derive(Clone, Serialize, Deserialize)]
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

#[derive(Clone, Serialize, Deserialize)]
pub struct TPMEventMixModel {
    pub event: TPMEventID,
    pub group: u32,
}

pub const PCR4_EFICALL: TPMEventMixModel = TPMEventMixModel {
    event: TPMEventID::Pcr4EfiCall,
    group: TPMEG_NEVER,
};
pub const PCR4_SEPARATOR: TPMEventMixModel = TPMEventMixModel {
    event: TPMEventID::Pcr4Separator,
    group: TPMEG_NEVER,
};
pub const PCR4_SHIM: TPMEventMixModel = TPMEventMixModel {
    event: TPMEventID::Pcr4Shim,
    group: TPMEG_BOOTLOADER,
};
pub const PCR4_GRUB: TPMEventMixModel = TPMEventMixModel {
    event: TPMEventID::Pcr4Shim,
    group: TPMEG_BOOTLOADER,
};
pub const PCR4_VMLINUZ: TPMEventMixModel = TPMEventMixModel {
    event: TPMEventID::Pcr4Vmlinuz,
    group: TPMEG_LINUX,
};
pub const PCR7_SECUREBOOT: TPMEventMixModel = TPMEventMixModel {
    event: TPMEventID::Pcr7SecureBoot,
    group: TPMEG_SECUREBOOT,
};
pub const PCR7_PK: TPMEventMixModel = TPMEventMixModel {
    event: TPMEventID::Pcr7Pk,
    group: TPMEG_SECUREBOOT,
};
pub const PCR7_KEK: TPMEventMixModel = TPMEventMixModel {
    event: TPMEventID::Pcr7Kek,
    group: TPMEG_SECUREBOOT,
};
pub const PCR7_DB: TPMEventMixModel = TPMEventMixModel {
    event: TPMEventID::Pcr7Db,
    group: TPMEG_SECUREBOOT,
};
pub const PCR7_DBX: TPMEventMixModel = TPMEventMixModel {
    event: TPMEventID::Pcr7Dbx,
    group: TPMEG_SECUREBOOT,
};
pub const PCR7_SEPARATOR: TPMEventMixModel = TPMEventMixModel {
    event: TPMEventID::Pcr7Separator,
    group: TPMEG_NEVER,
};
pub const PCR7_SHIMCERT: TPMEventMixModel = TPMEventMixModel {
    event: TPMEventID::Pcr7ShimCert,
    group: TPMEG_SECUREBOOT | TPMEG_BOOTLOADER,
};
// Secure boot on/off also changes the logged sbatlevel
pub const PCR7_SBATLEVEL: TPMEventMixModel = TPMEventMixModel {
    event: TPMEventID::Pcr7SbatLevel,
    group: TPMEG_SECUREBOOT | TPMEG_BOOTLOADER,
};
pub const PCR7_GRUBDBCERT: TPMEventMixModel = TPMEventMixModel {
    event: TPMEventID::Pcr7GrubDbCert,
    group: TPMEG_SECUREBOOT | TPMEG_BOOTLOADER,
};
pub const PCR7_GRUBVENDORDBCERT: TPMEventMixModel = TPMEventMixModel {
    event: TPMEventID::Pcr7GrubVendorDbCert,
    group: TPMEG_SECUREBOOT | TPMEG_BOOTLOADER,
};
pub const PCR7_GRUBMOKLISTCERT: TPMEventMixModel = TPMEventMixModel {
    event: TPMEventID::Pcr7GrubMokListCert,
    group: TPMEG_SECUREBOOT | TPMEG_BOOTLOADER | TPMEG_MOKVARS,
};
pub const PCR11_LINUX: TPMEventMixModel = TPMEventMixModel {
    event: TPMEventID::Pcr11Linux,
    group: TPMEG_UKI,
};
pub const PCR11_LINUX_CONTENT: TPMEventMixModel = TPMEventMixModel {
    event: TPMEventID::Pcr11LinuxContent,
    group: TPMEG_UKI,
};
pub const PCR11_OSREL: TPMEventMixModel = TPMEventMixModel {
    event: TPMEventID::Pcr11Osrel,
    group: TPMEG_UKI,
};
pub const PCR11_OSREL_CONTENT: TPMEventMixModel = TPMEventMixModel {
    event: TPMEventID::Pcr11OsrelContent,
    group: TPMEG_UKI,
};
pub const PCR11_CMDLINE: TPMEventMixModel = TPMEventMixModel {
    event: TPMEventID::Pcr11Cmdline,
    group: TPMEG_UKI,
};
pub const PCR11_CMDLINE_CONTENT: TPMEventMixModel = TPMEventMixModel {
    event: TPMEventID::Pcr11CmdlineContent,
    group: TPMEG_UKI,
};
pub const PCR11_INITRD: TPMEventMixModel = TPMEventMixModel {
    event: TPMEventID::Pcr11Initrd,
    group: TPMEG_UKI,
};
pub const PCR11_INITRD_CONTENT: TPMEventMixModel = TPMEventMixModel {
    event: TPMEventID::Pcr11InitrdContent,
    group: TPMEG_UKI,
};
pub const PCR11_UNAME: TPMEventMixModel = TPMEventMixModel {
    event: TPMEventID::Pcr11Uname,
    group: TPMEG_UKI,
};
pub const PCR11_UNAME_CONTENT: TPMEventMixModel = TPMEventMixModel {
    event: TPMEventID::Pcr11UnameContent,
    group: TPMEG_UKI,
};
pub const PCR11_SBAT: TPMEventMixModel = TPMEventMixModel {
    event: TPMEventID::Pcr11Sbat,
    group: TPMEG_UKI,
};
pub const PCR11_SBAT_CONTENT: TPMEventMixModel = TPMEventMixModel {
    event: TPMEventID::Pcr11SbatContent,
    group: TPMEG_UKI,
};
pub const PCR14_MOKLIST: TPMEventMixModel = TPMEventMixModel {
    event: TPMEventID::Pcr14MokList,
    group: TPMEG_MOKVARS,
};
pub const PCR14_MOKLISTX: TPMEventMixModel = TPMEventMixModel {
    event: TPMEventID::Pcr14MokListX,
    group: TPMEG_MOKVARS,
};
pub const PCR14_MOKLISTTRUSTED: TPMEventMixModel = TPMEventMixModel {
    event: TPMEventID::Pcr14MokListTrusted,
    group: TPMEG_MOKVARS,
};

#[serde_as]
#[derive(Clone, Serialize, Deserialize)]
pub struct TPMEvent {
    pub name: String,
    pub pcr: u8,
    #[serde_as(as = "serde_with::hex::Hex")]
    pub hash: Vec<u8>,
    pub mix: TPMEventMixModel,
}

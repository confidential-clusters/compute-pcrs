// SPDX-FileCopyrightText: Timothée Ravier <tim@siosm.fr>
// SPDX-FileCopyrightText: Beñat Gartzia Arruabarrena <bgartzia@redhat.com>
// SPDX-FileCopyrightText: Jakob Naucke <jnaucke@redhat.com>
//
// SPDX-License-Identifier: MIT

use sha2::{Digest, Sha256};

pub use pcrs::{Part, Pcr};

pub mod certs;
mod esp;
mod linux;
mod mok;
pub mod pcrs;
pub mod pefile;
pub mod rootfs;
pub mod shim;
pub mod tpmevents;
pub mod uefi;

pub fn compute_pcr4(kernels_dir: &str, esp_path: &str, uki: bool, secureboot: bool) -> Pcr {
    let events = tpmevents::compute::pcr4_events(kernels_dir, esp_path, uki, secureboot);
    Pcr::compile_from(&events)
}

pub fn compute_pcr11(uki: &str) -> Pcr {
    Pcr::compile_from(&tpmevents::compute::pcr11_events(uki))
}

/// PCR 7 contains the digests of the variables defining the Secure Boot
/// state. It's extended by the following events:
///    - EV_EFI_VARIABLE_DRIVER_CONFIG: SecureBoot
///    - EV_EFI_VARIABLE_DRIVER_CONFIG: PK
///    - EV_EFI_VARIABLE_DRIVER_CONFIG: KEK
///    - EV_EFI_VARIABLE_DRIVER_CONFIG: db
///    - EV_EFI_VARIABLE_DRIVER_CONFIG: dbx
///    - EV_SEPARATOR
///    - EV_EFI_VARIABLE_AUTHORITY: db
///    - EV_EFI_VARIABLE_AUTHORITY: SbatLevel
///    - EV_EFI_VARIABLE_AUTHORITY: MokListRT
///
/// EFI vars are needed to compute pcr7.
/// EFI vars can be loaded from
///     - efivars
///
pub fn compute_pcr7(efivars_path: Option<&str>, esp_path: &str, secureboot_enabled: bool) -> Pcr {
    let events = tpmevents::compute::pcr7_events(
        efivars_path.expect("No efivars directory path provided"),
        esp_path,
        secureboot_enabled,
    );

    Pcr::compile_from(&events)
}

pub fn compute_pcr14(mok_variables: &str) -> Pcr {
    let mok_event_loader = mok::MokEventHashes::new(mok_variables);

    let elems: Vec<(String, Vec<u8>)> = mok_event_loader.map(|h| ("EV_IPL".into(), h)).collect();

    let mut result =
        hex::decode("0000000000000000000000000000000000000000000000000000000000000000")
            .unwrap()
            .to_vec();
    for (_, h) in &elems {
        let mut hasher = Sha256::new();
        hasher.update(result);
        hasher.update(h);
        result = hasher.finalize().to_vec();
    }

    Pcr {
        id: 14,
        value: result,
        parts: elems
            .iter()
            .map(|(e, h)| Part {
                name: e.clone(),
                hash: h.to_vec(),
            })
            .collect(),
    }
}

// SPDX-FileCopyrightText: Timothée Ravier <tim@siosm.fr>
// SPDX-FileCopyrightText: Beñat Gartzia Arruabarrena <bgartzia@redhat.com>
//
// SPDX-License-Identifier: MIT
use sha2::{Digest, Sha256};

use crate::esp;
use crate::linux;
use crate::tpmevents;
use crate::tpmevents::TPMEvent;

const EV_SEPARATOR_HASH: [u8; 32] = [
    223, 63, 97, 152, 4, 169, 47, 219, 64, 87, 25, 45, 196, 61, 215, 72, 234, 119, 138, 220, 82,
    188, 73, 140, 232, 5, 36, 192, 20, 184, 17, 25,
];

pub fn pcr4_events(
    kernels_dir: &str,
    esp_path: &str,
    uki: bool,
    secureboot: bool,
) -> Vec<TPMEvent> {
    let mut events: Vec<TPMEvent> = vec![];
    let esp = esp::Esp::new(esp_path).unwrap();
    let n_pcr = 4;

    // Calling EFI App
    events.push(TPMEvent {
        name: "EV_EFI_ACTION".into(),
        pcr: n_pcr,
        hash: Sha256::digest(b"Calling EFI Application from Boot Option").to_vec(),
        mix: tpmevents::PCR4_EFICALL,
    });

    // Separator
    events.push(TPMEvent {
        name: "EV_SEPARATOR".into(),
        pcr: n_pcr,
        hash: EV_SEPARATOR_HASH.to_vec(),
        mix: tpmevents::PCR4_SEPARATOR,
    });

    // Binaries
    events.push(TPMEvent {
        name: "EV_EFI_BOOT_SERVICES_APPLICATION".into(),
        pcr: n_pcr,
        hash: esp.shim().authenticode(),
        mix: tpmevents::PCR4_SHIM,
    });

    events.push(TPMEvent {
        name: "EV_EFI_BOOT_SERVICES_APPLICATION".into(),
        pcr: n_pcr,
        hash: esp.grub().authenticode(),
        mix: tpmevents::PCR4_GRUB,
    });

    if secureboot && !uki {
        events.push(TPMEvent {
            name: "EV_EFI_BOOT_SERVICES_APPLICATION".into(),
            pcr: n_pcr,
            hash: linux::load_vmlinuz(kernels_dir).unwrap().authenticode(),
            mix: tpmevents::PCR4_VMLINUZ,
        });
    }

    // TODO: write condition for uki and implement logic
    events
}

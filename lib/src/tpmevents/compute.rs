// SPDX-FileCopyrightText: Timothée Ravier <tim@siosm.fr>
// SPDX-FileCopyrightText: Beñat Gartzia Arruabarrena <bgartzia@redhat.com>
//
// SPDX-License-Identifier: MIT
use lief::generic::Section;
use sha2::{Digest, Sha256};
use std::collections::HashSet;

use crate::esp;
use crate::linux;
use crate::mok;
use crate::shim;
use crate::tpmevents;
use crate::tpmevents::TPMEvent;
use crate::uefi;
use crate::uefi::efivars;

const EV_SEPARATOR_HASH: [u8; 32] = [
    223, 63, 97, 152, 4, 169, 47, 219, 64, 87, 25, 45, 196, 61, 215, 72, 234, 119, 138, 220, 82,
    188, 73, 140, 232, 5, 36, 192, 20, 184, 17, 25,
];
const MODELS_SB_VARIABLES: [tpmevents::TPMEventMixModel; 4] = [
    tpmevents::PCR7_PK,
    tpmevents::PCR7_KEK,
    tpmevents::PCR7_DB,
    tpmevents::PCR7_DBX,
];
const MODELS_UKI_SECTION_NAME: [tpmevents::TPMEventMixModel; 6] = [
    tpmevents::PCR11_LINUX,
    tpmevents::PCR11_OSREL,
    tpmevents::PCR11_CMDLINE,
    tpmevents::PCR11_INITRD,
    tpmevents::PCR11_UNAME,
    tpmevents::PCR11_SBAT,
];
const MODELS_UKI_SECTION_CONTENT: [tpmevents::TPMEventMixModel; 6] = [
    tpmevents::PCR11_LINUX_CONTENT,
    tpmevents::PCR11_OSREL_CONTENT,
    tpmevents::PCR11_CMDLINE_CONTENT,
    tpmevents::PCR11_INITRD_CONTENT,
    tpmevents::PCR11_UNAME_CONTENT,
    tpmevents::PCR11_SBAT_CONTENT,
];
const MODELS_MOKVARS: [tpmevents::TPMEventMixModel; 3] = [
    tpmevents::PCR14_MOKLIST,
    tpmevents::PCR14_MOKLISTX,
    tpmevents::PCR14_MOKLISTTRUSTED,
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

pub fn pcr7_events(efivars_path: &str, esp_path: &str, secureboot_enabled: bool) -> Vec<TPMEvent> {
    let n_pcr = 7;
    let sb_var_loader =
        efivars::EFIVarsLoader::new(efivars_path, efivars::SECURE_BOOT_ATTR_HEADER_LENGTH);
    let esp = esp::Esp::new(esp_path).unwrap();
    let shim_bin = esp.shim();
    let sbatlevel_raw = shim_bin.section(shim::SHIM_SBATLEVEL_SECTION);
    let sb_db = sb_var_loader.secureboot_db();
    let sb_db_certs = crate::certs::get_db_certs(&sb_db).unwrap();
    let mut events: Vec<TPMEvent> = vec![];

    // Secure boot state: enabled/disabled
    events.push(TPMEvent {
        name: "EV_EFI_VARIABLE_DRIVER_CONFIG".into(),
        pcr: n_pcr,
        hash: uefi::get_secureboot_state_event(secureboot_enabled).hash(),
        mix: tpmevents::PCR7_SECUREBOOT,
    });

    // Secure boot variables: PK, KEK, db, dbx
    for (model, var) in MODELS_SB_VARIABLES.iter().zip(sb_var_loader) {
        events.push(TPMEvent {
            name: "EV_EFI_VARIABLE_DRIVER_CONFIG".into(),
            pcr: n_pcr,
            hash: var.hash(),
            mix: model.clone(),
        });
    }

    // Separator
    events.push(TPMEvent {
        name: "EV_SEPARATOR".into(),
        pcr: n_pcr,
        hash: EV_SEPARATOR_HASH.to_vec(),
        mix: tpmevents::PCR7_SEPARATOR,
    });

    // Shim certs
    if secureboot_enabled {
        match shim_bin.find_cert_in_db(&sb_db_certs) {
            Some(cert) => events.push(TPMEvent {
                name: "EV_EFI_VARIABLE_AUTHORITY".into(),
                pcr: n_pcr,
                hash: uefi::UEFIVariableData::new(uefi::GUID_SECURITY_DATABASE, "db", cert).hash(),
                mix: tpmevents::PCR7_SHIMCERT,
            }),
            None => panic!("Can't find shim signature certificate in secure boot db"),
        }
    }

    // Sbat level
    if sbatlevel_raw.is_none() || !secureboot_enabled {
        events.push(TPMEvent {
            name: "EV_EFI_VARIABLE_AUTHORITY".into(),
            pcr: n_pcr,
            hash: shim::get_sbat_var_original_uefivar().hash(),
            mix: tpmevents::PCR7_SBATLEVEL,
        });
    } else if let Some(data) = sbatlevel_raw {
        let sbatlevel = shim::get_sbatlevel_uefivar(&data, &shim::SbatLevelPolicyType::PREVIOUS);
        events.push(TPMEvent {
            name: "EV_EFI_VARIABLE_AUTHORITY".into(),
            pcr: n_pcr,
            hash: sbatlevel.hash(),
            mix: tpmevents::PCR7_SBATLEVEL,
        });
    }

    // Certs used to verify binaries loaded by shim
    if secureboot_enabled {
        let mut logged_cert_hashes = HashSet::new();
        let shim_vendor_cert = shim_bin.vendor_cert();
        let shim_vendor_db = shim_bin.vendor_db();
        // TODO: In the case of UKI, the UKI and UKI addons should be processed
        let binaries = vec![esp.grub()];
        for bin in binaries {
            // look for cert in secureboot
            if let Some(sb_cert) = bin.find_cert_in_db(&sb_db_certs) {
                let hash =
                    uefi::UEFIVariableData::new(uefi::GUID_SECURITY_DATABASE, "db", sb_cert).hash();
                if !logged_cert_hashes.contains(&hash) {
                    logged_cert_hashes.insert(hash.clone());
                    events.push(TPMEvent {
                        name: "EV_EFI_VARIABLE_AUTHORITY".into(),
                        pcr: n_pcr,
                        hash,
                        mix: tpmevents::PCR7_GRUBDBCERT,
                    });
                }
            }

            // look for cert in shim vendor db
            if let Some(vendor_db) = bin.find_cert_in_db(&shim_vendor_db) {
                let hash = uefi::UEFIVariableData::new(
                    uefi::GUID_SECURITY_DATABASE,
                    "vendor_db",
                    vendor_db,
                )
                .hash();
                if !logged_cert_hashes.contains(&hash) {
                    logged_cert_hashes.insert(hash.clone());
                    events.push(TPMEvent {
                        name: "EV_EFI_VARIABLE_AUTHORITY".into(),
                        pcr: n_pcr,
                        hash,
                        mix: tpmevents::PCR7_GRUBVENDORDBCERT,
                    });
                }
            }

            // look for cert in shim vendor cert
            if let Some(vendor_cert) = bin.find_cert_in_db(&shim_vendor_cert) {
                let mut vendor_cert_data = uefi::guid_to_le_bytes(&uefi::GUID_SHIM_LOCK);
                vendor_cert_data.extend(&vendor_cert);
                let hash = uefi::UEFIVariableData::new(
                    uefi::GUID_SHIM_LOCK,
                    "MokListRT",
                    vendor_cert_data,
                )
                .hash();
                if !logged_cert_hashes.contains(&hash) {
                    logged_cert_hashes.insert(hash.clone());
                    events.push(TPMEvent {
                        name: "EV_EFI_VARIABLE_AUTHORITY".into(),
                        pcr: n_pcr,
                        hash,
                        mix: tpmevents::PCR7_GRUBMOKLISTCERT,
                    });
                }
            }
        }
    }

    events
}

pub fn pcr11_events(uki: &str) -> Vec<TPMEvent> {
    let n_pcr = 11;
    let sections: Vec<&str> = vec![".linux", ".osrel", ".cmdline", ".initrd", ".uname", ".sbat"];
    let pe: lief::pe::Binary = lief::pe::Binary::parse(uki).unwrap();
    let mut events: Vec<TPMEvent> = vec![];

    sections
        .iter()
        .zip(MODELS_UKI_SECTION_NAME)
        .zip(MODELS_UKI_SECTION_CONTENT)
        .for_each(|((s, nm), cm)| {
            let section = pe.section_by_name(s).unwrap();
            events.push(TPMEvent {
                name: (*s).into(),
                pcr: n_pcr,
                hash: Sha256::digest(format!("{s}\0")).to_vec(),
                mix: nm,
            });
            events.push(TPMEvent {
                name: format!("{}_CONTENT", *s),
                pcr: n_pcr,
                hash: Sha256::digest(section.content()).to_vec(),
                mix: cm,
            });
        });

    events
}

pub fn pcr14_events(mok_variables: &str) -> Vec<TPMEvent> {
    let n_pcr = 14;
    mok::MokEventHashes::new(mok_variables)
        .zip(MODELS_MOKVARS)
        .map(|(h, m)| TPMEvent {
            name: "EV_IPL".into(),
            pcr: n_pcr,
            hash: h,
            mix: m,
        })
        .collect()
}

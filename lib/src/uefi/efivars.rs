// SPDX-FileCopyrightText: Timothée Ravier <tim@siosm.fr>
// SPDX-FileCopyrightText: Beñat Gartzia Arruabarrena <bgartzia@redhat.com>
//
// SPDX-License-Identifier: MIT

use super::{GUID_GLOBAL_VARIABLE, GUID_SECURITY_DATABASE, UEFIVariableData};
use crate::uefi::secureboot;
use std::fs;
use std::path::{Path, PathBuf};
use uuid::Uuid;

const EFI_VAR_ID_PK: (&str, Uuid) = ("PK", GUID_GLOBAL_VARIABLE);
const EFI_VAR_ID_KEK: (&str, Uuid) = ("KEK", GUID_GLOBAL_VARIABLE);
const EFI_VAR_ID_DB: (&str, Uuid) = ("db", GUID_SECURITY_DATABASE);
const EFI_VAR_ID_DBX: (&str, Uuid) = ("dbx", GUID_SECURITY_DATABASE);

const SECURE_BOOT_VARIABLES: [(&str, Uuid); 4] =
    [EFI_VAR_ID_PK, EFI_VAR_ID_KEK, EFI_VAR_ID_DB, EFI_VAR_ID_DBX];

pub const SECURE_BOOT_ATTR_HEADER_LENGTH: usize = 4;

#[derive(Debug, Clone)]
pub struct EFIVarsLoader {
    path: PathBuf,
    attribute_header: usize,
    index: usize,
}

impl EFIVarsLoader {
    pub fn new(path: &str, attribute_header: usize) -> EFIVarsLoader {
        EFIVarsLoader {
            path: path.into(),
            attribute_header,
            index: 0,
        }
    }

    fn load_efivar(&self, guid: &uuid::Uuid, var: &str) -> UEFIVariableData {
        let data = load_uefi_var_data(&self.path, var, guid, self.attribute_header);
        UEFIVariableData::new(*guid, var, data)
    }
}

impl Iterator for EFIVarsLoader {
    type Item = UEFIVariableData;

    fn next(&mut self) -> Option<Self::Item> {
        let (var, guid) = SECURE_BOOT_VARIABLES.get(self.index)?;
        self.index += 1;
        Some(self.load_efivar(guid, var))
    }
}

impl secureboot::SecureBootdbLoader for EFIVarsLoader {
    fn secureboot_db(&self) -> Vec<u8> {
        let (var, guid) = EFI_VAR_ID_DB;
        load_uefi_var_data(&self.path, var, &guid, self.attribute_header)
    }
}

impl secureboot::SecureBootVarLoader for EFIVarsLoader {}

pub fn get_secure_boot_targets() -> Vec<(String, Uuid)> {
    SECURE_BOOT_VARIABLES
        .map(|(var, guid)| (var.into(), guid))
        .to_vec()
}

/// Load data from a UEFI variable given:
///     - path to the directory holding the file
///     - var, UEFI variable name
///     - guid
///     - attribute header length
fn load_uefi_var_data(path: &Path, var: &str, guid: &Uuid, attribute_header: usize) -> Vec<u8> {
    let mut data = match fs::read(path.join(format!("{var}-{guid}"))) {
        Ok(res) => res,
        Err(err) => {
            let path_md = fs::metadata(path).unwrap();
            if err.kind() == std::io::ErrorKind::NotFound && path_md.is_dir() {
                return vec![];
            }
            panic!("{err:?}");
        }
    };
    if attribute_header > 0 {
        return data.split_off(attribute_header);
    }
    data
}

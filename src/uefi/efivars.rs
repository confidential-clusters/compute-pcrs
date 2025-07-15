use super::{GUID_GLOBAL_VARIABLE, GUID_SECURITY_DATABASE, UEFIVariableData};
use std::path::{Path, PathBuf};
use uuid::Uuid;

const EFI_VAR_ID_PK: (&str, Uuid) = ("PK", GUID_GLOBAL_VARIABLE);
const EFI_VAR_ID_KEK: (&str, Uuid) = ("KEK", GUID_GLOBAL_VARIABLE);
const EFI_VAR_ID_DB: (&str, Uuid) = ("db", GUID_SECURITY_DATABASE);
const EFI_VAR_ID_DBX: (&str, Uuid) = ("dbx", GUID_SECURITY_DATABASE);

const SECURE_BOOT_VARIABLES: [(&str, Uuid); 4] =
    [EFI_VAR_ID_PK, EFI_VAR_ID_KEK, EFI_VAR_ID_DB, EFI_VAR_ID_DBX];

pub const SECURE_BOOT_ATTR_HEADER_LENGTH: usize = 4;

pub struct EFIVarsLoader {
    path: PathBuf,
    attribute_header: usize,
    index: usize,
    targets: Vec<(String, Uuid)>,
}

pub fn load_db(path: &str) -> UEFIVariableData {
    let (var, guid) = EFI_VAR_ID_DB;
    UEFIVariableData::load(Path::new(path), var, guid, SECURE_BOOT_ATTR_HEADER_LENGTH)
}

impl EFIVarsLoader {
    pub fn new(
        path: &str,
        attribute_header: usize,
        variables: Vec<(String, Uuid)>,
    ) -> EFIVarsLoader {
        EFIVarsLoader {
            path: path.into(),
            attribute_header,
            index: 0,
            targets: variables,
        }
    }
}

impl Iterator for EFIVarsLoader {
    type Item = UEFIVariableData;

    fn next(&mut self) -> Option<Self::Item> {
        let (var, guid) = self.targets.get(self.index)?;
        self.index += 1;
        Some(UEFIVariableData::load(
            &self.path,
            var,
            *guid,
            self.attribute_header,
        ))
    }
}

pub fn get_secure_boot_targets() -> Vec<(String, Uuid)> {
    SECURE_BOOT_VARIABLES
        .map(|(var, guid)| (var.into(), guid))
        .to_vec()
}

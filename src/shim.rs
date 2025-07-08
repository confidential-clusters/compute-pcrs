use crate::uefi::{GUID_SHIM_LOCK, UEFIVariableData};
use lief::generic::Section;

pub struct Shim {
    image: lief::pe::Binary,
}

const SHIM_SBATLEVEL_SECTION: &str = ".sbatlevel";
const SBAT_VAR_ORIGINAL: &str = "sbat,1,2021030218\n";

impl Shim {
    pub fn load_from_file(path: &str) -> Shim {
        Shim {
            image: lief::pe::Binary::parse(path).unwrap(),
        }
    }

    pub fn get_sbatlevel_uefivar(&self) -> Option<UEFIVariableData> {
        for section in self.image.sections() {
            if section.name() == *SHIM_SBATLEVEL_SECTION {
                return Some(UEFIVariableData::new(
                    GUID_SHIM_LOCK,
                    "SbatLevel",
                    section.content().to_vec(),
                ));
            }
        }
        None
    }
}

pub fn get_sbat_var_original_uefivar() -> UEFIVariableData {
    UEFIVariableData::new(GUID_SHIM_LOCK, "SbatLevel", SBAT_VAR_ORIGINAL.into())
}

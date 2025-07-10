use crate::uefi::{GUID_SHIM_LOCK, UEFIVariableData};
use lief::generic::Section;
use std::fs::File;
use std::os::unix::fs::FileExt;

pub struct Shim {
    image: lief::pe::Binary,
    path: String,
}

const SHIM_SBATLEVEL_SECTION: &str = ".sbatlevel";
const SBAT_VAR_ORIGINAL: &str = "sbat,1,2021030218\n";

impl Shim {
    pub fn load_from_file(path: &str) -> Shim {
        Shim {
            image: lief::pe::Binary::parse(path).unwrap(),
            path: path.into(),
        }
    }

    pub fn image(&self) -> &lief::pe::Binary {
        &self.image
    }

    fn long_section_name(&self, mut name: String) -> String {
        if name.as_bytes()[0] as char != '/' {
            return name;
        }
        name.remove(0);
        // Symbols are 18 bytes long
        let mut string_offset = self.image.header().pointerto_symbol_table()
            + self.image.header().numberof_symbols() * 18
            + name.parse::<u32>().unwrap();
        let mut long_name = String::new();
        let mut next_char: [u8; 1] = [0];
        loop {
            let image_file = File::open(&self.path).unwrap();
            if image_file
                .read_exact_at(&mut next_char, string_offset as u64)
                .is_err()
                || next_char[0] == 0
            {
                break;
            }

            long_name.push(next_char[0] as char);
            string_offset += 1;
        }
        long_name
    }

    pub fn get_sbatlevel_uefivar(&self) -> Option<UEFIVariableData> {
        for section in self.image.sections() {
            if self.long_section_name(section.name()) == *SHIM_SBATLEVEL_SECTION {
                return Some(UEFIVariableData::new(
                    GUID_SHIM_LOCK,
                    "SbatLevel",
                    section.content().to_vec(),
                ));
            }
        }
        None
    }

    pub fn signatures(&self) -> lief::pe::signature::Signatures {
        self.image.signatures()
    }
}

pub fn get_sbat_var_original_uefivar() -> UEFIVariableData {
    UEFIVariableData::new(GUID_SHIM_LOCK, "SbatLevel", SBAT_VAR_ORIGINAL.into())
}

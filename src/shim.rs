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

pub enum SbatLevelPolicyType {
    PREVIOUS,
    LATEST,
}

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

    pub fn get_sbatlevel_uefivar(
        &self,
        sbatlevel_policy: &SbatLevelPolicyType,
    ) -> Option<UEFIVariableData> {
        for section in self.image.sections() {
            if self.long_section_name(section.name()) == *SHIM_SBATLEVEL_SECTION {
                return Some(UEFIVariableData::new(
                    GUID_SHIM_LOCK,
                    "SbatLevel",
                    get_sbatlevel_section(section.content(), sbatlevel_policy),
                ));
            }
        }
        None
    }

    pub fn signatures(&self) -> lief::pe::signature::Signatures {
        self.image.signatures()
    }

    pub fn find_cert_in_db(&self, db: &Vec<crate::certs::X509Cert>) -> Option<Vec<u8>> {
        for signature in self.signatures() {
            for certificate in signature.certificates() {
                let shim_cert_subject = certificate.subject();
                let shim_cert_issuer = certificate.issuer();
                for cert in db {
                    if cert.subject == shim_cert_subject || cert.subject == shim_cert_issuer {
                        return Some(cert.raw.clone());
                    }
                }
            }
        }
        None
    }
}

pub fn get_sbat_var_original_uefivar() -> UEFIVariableData {
    UEFIVariableData::new(GUID_SHIM_LOCK, "SbatLevel", SBAT_VAR_ORIGINAL.into())
}

// Given the raw .sbatlevel section data, it returns the .sbatlevel data of the
// target sbatlevel policy, which can be previous or latest.
//
// The .sbatlevel section contains a 3*u32 header struct consisting of:
//  - version
//  - previous .sbatlevel policy section offset
//  - latest .sbatlevel policy section offset
fn get_sbatlevel_section(sbatlevel_raw: &[u8], sbatlevel_policy: &SbatLevelPolicyType) -> Vec<u8> {
    let raw_len = sbatlevel_raw.len();
    assert!(raw_len > 12, "Unknown sbatlevel data format: too short");

    let policy_offset: usize = match sbatlevel_policy {
        SbatLevelPolicyType::PREVIOUS => u32::from_le_bytes(
            sbatlevel_raw[4..8]
                .try_into()
                .expect("Badly hardcoded section size"),
        ) as usize,
        SbatLevelPolicyType::LATEST => u32::from_le_bytes(
            sbatlevel_raw[8..12]
                .try_into()
                .expect("Badly hardcoded section size"),
        ) as usize,
    } + 4;
    assert!(
        raw_len > policy_offset + 1,
        "Unknown sbatlevel data format: too short"
    );

    let mut policy_end: usize = policy_offset;
    loop {
        let next_char = sbatlevel_raw[policy_end];
        if next_char == 0 {
            break;
        }
        policy_end += 1;
    }

    sbatlevel_raw[policy_offset..policy_end].to_vec()
}

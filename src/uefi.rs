use sha2::{Digest, Sha256};
use std::fs;
use std::path::Path;
use uuid::{Uuid, uuid};

pub mod efivars;

pub const GUID_GLOBAL_VARIABLE: Uuid = uuid!("8be4df61-93ca-11d2-aa0d-00e098032b8c");
pub const GUID_SECURITY_DATABASE: Uuid = uuid!("d719b2cb-3d3a-4596-a3bc-dad00e67656f");
pub const GUID_SHIM_LOCK: Uuid = uuid!("605dab50-e046-4300-abb6-3dd810dd8b23");

pub const EFI_CERT_TYPE_X509_GUID: Uuid = uuid!("a5c059a1-94e4-4aa7-87b5-ab155c2bf072");

// Generates the little endian representation of a GUID variable
// name.
fn guid_to_le_bytes(guid: &Uuid) -> Vec<u8> {
    let mut guid_bytes_le: Vec<u8> = guid.as_bytes().to_vec();

    guid_bytes_le[0..4].reverse();
    guid_bytes_le[4..6].reverse();
    guid_bytes_le[6..8].reverse();
    // Bytes from 8 on are not reversed
    guid_bytes_le
}

/// Load data from a UEFI variable given:
///     - path to the directory holding the file
///     - var, UEFI variable name
///     - guid
///     - attribute header length
fn load_uefi_var_data(path: &Path, var: &str, guid: &Uuid, attribute_header: usize) -> Vec<u8> {
    let mut data = fs::read(path.join(format!("{var}-{guid}"))).unwrap();
    if attribute_header > 0 {
        return data.split_off(attribute_header);
    }
    data
}

/// Finds the certificates that UEFI db contains given its raw representation
/// Returns X509 structures and their raw representation
fn get_db_certs(data: &[u8]) -> Vec<(openssl::x509::X509, Vec<u8>)> {
    let mut certs = Vec::new();
    let mut offset = 0;

    while offset < data.len() - 28 {
        let list_type = &data[offset..offset + 16];
        let list_size = u32::from_le_bytes(
            data[offset + 16..offset + 20]
                .try_into()
                .expect("Badly hardcoded section size"),
        ) as usize;
        let head_size = u32::from_le_bytes(
            data[offset + 20..offset + 24]
                .try_into()
                .expect("Badly hardcoded section size"),
        ) as usize;
        let item_size = u32::from_le_bytes(
            data[offset + 24..offset + 28]
                .try_into()
                .expect("Badly hardcoded section size"),
        ) as usize;

        if offset + list_size > data.len() {
            panic!("Invalid list size");
        }

        offset += 28 + head_size;
        let mut item_offset = 0;

        if list_type == guid_to_le_bytes(&EFI_CERT_TYPE_X509_GUID) {
            while item_offset < list_size - (head_size + 28) {
                let item = &data[offset + item_offset..offset + item_offset + item_size];
                if let Ok(c) = openssl::x509::X509::from_der(&item[16..]) {
                    certs.push((c, item.into()));
                }
                item_offset += item_size;
            }
        }
        offset += list_size - (28 + head_size)
    }

    certs
}

// For a certificate db, it returns a vector containing tuples of certificate
// subjects, issuers and certificate's raw representation
fn get_db_subject_issuer_raw(data: &[u8]) -> Vec<(String, Vec<u8>)> {
    // cert.{subject,issuer}_name().entries()
    fn cert_subject(cert: &openssl::x509::X509) -> String {
        fn entry_to_string(entry: &openssl::x509::X509NameEntryRef) -> Option<String> {
            // TODO improve the way both object is formatted to str
            let object = format!("{:?}", entry.object());
            let data = entry.data().as_utf8().unwrap();
            let data_str = std::str::from_utf8(data.as_bytes()).unwrap();
            if object == "countryName" {
                return Some(format!("C={}", data_str));
            } else if object == "stateOrProvinceName" {
                return Some(format!("ST={}", data_str));
            } else if object == "localityName" {
                return Some(format!("L={}", data_str));
            } else if object == "organizationName" {
                return Some(format!("O={}", data_str));
            } else if object == "commonName" {
                return Some(format!("CN={}", data_str));
            }
            None
        }

        cert.subject_name()
            .entries()
            .filter_map(entry_to_string)
            .collect::<Vec<_>>()
            .join(", ")
    }

    get_db_certs(data)
        .iter()
        .map(|(c, r)| (cert_subject(c), r.clone()))
        .collect()
}

pub fn find_shim_cert_in_db(sb_db: &[u8], shim: &crate::shim::Shim) -> Option<Vec<u8>> {
    let sb_db_certs = get_db_subject_issuer_raw(sb_db);
    for signature in shim.signatures() {
        for certificate in signature.certificates() {
            let shim_cert_subject = certificate.subject();
            let shim_cert_issuer = certificate.issuer();
            for (db_subject, db_raw) in &sb_db_certs {
                if *db_subject == shim_cert_subject || *db_subject == shim_cert_issuer {
                    return Some(db_raw.clone());
                }
            }
        }
    }
    None
}

pub fn get_secureboot_state_event(enabled: bool) -> UEFIVariableData {
    UEFIVariableData::new(
        GUID_GLOBAL_VARIABLE,
        "SecureBoot",
        match enabled {
            true => vec![enabled as u8],
            false => vec![],
        },
    )
}

// Struct representing UEFIVariable data and the events it could measure in
// the TPM
pub struct UEFIVariableData {
    variable_name: Uuid,
    unicode_name_len: u64,
    data_len: u64,
    unicode_name: Vec<u16>,
    variable_data: Vec<u8>,
}

impl UEFIVariableData {
    // Create a UEFIVariableData with:
    //    - A UEFI GUID variable name Uuid (32 digit hexadecimal string).
    //    - The unicode variable name String.
    //    - Buffer containing the variable data.
    pub fn new(variable_name: Uuid, unicode_name: &str, data: Vec<u8>) -> UEFIVariableData {
        UEFIVariableData {
            variable_name,
            unicode_name_len: unicode_name.len() as u64,
            data_len: data.len() as u64,
            unicode_name: unicode_name.encode_utf16().collect(),
            variable_data: data,
        }
    }

    pub fn load(path: &Path, var: &str, guid: Uuid, attribute_header: usize) -> UEFIVariableData {
        let data = load_uefi_var_data(path, var, &guid, attribute_header);
        UEFIVariableData::new(guid, var, data)
    }

    // Encode the UEFIVariableData struct into a u8 vec/buffer that can be
    // hashed.
    // This method returns the content that is hashed to obtain the event hash
    // that extends the TPM
    fn encode(&self) -> Vec<u8> {
        // Make a u8 buffer from the char16 representation of the unicode name
        let unicode_name_u8: Vec<u8> = self
            .unicode_name
            .iter()
            .flat_map(|x| x.to_le_bytes())
            .collect();
        [
            guid_to_le_bytes(&self.variable_name),
            self.unicode_name_len.to_le_bytes().to_vec(),
            self.data_len.to_le_bytes().to_vec(),
            unicode_name_u8,
            self.variable_data.clone(),
        ]
        .iter()
        .flat_map(|x| x.to_vec())
        .collect()
    }

    // Calculate the hash that will be measured in a TPM event
    pub fn hash(&self) -> Vec<u8> {
        Sha256::digest(self.encode()).to_vec()
    }

    pub fn data(&self) -> &[u8] {
        &self.variable_data
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;

    #[test]
    fn correct_hash() {
        let uefivar = UEFIVariableData::new(
            uuid!("8be4df61-93ca-11d2-aa0d-00e098032b8c"),
            "SecureBoot",
            vec![1],
        );
        assert_eq!(
            uefivar.hash(),
            hex!("ccfc4bb32888a345bc8aeadaba552b627d99348c767681ab3141f5b01e40a40e").to_vec()
        )
    }
}

use sha2::{Digest, Sha256};
use uuid::{Uuid, uuid};

pub mod efivars;
pub mod secureboot;

pub const GUID_GLOBAL_VARIABLE: Uuid = uuid!("8be4df61-93ca-11d2-aa0d-00e098032b8c");
pub const GUID_SECURITY_DATABASE: Uuid = uuid!("d719b2cb-3d3a-4596-a3bc-dad00e67656f");
pub const GUID_SHIM_LOCK: Uuid = uuid!("605dab50-e046-4300-abb6-3dd810dd8b23");

pub const EFI_CERT_TYPE_X509_GUID: Uuid = uuid!("a5c059a1-94e4-4aa7-87b5-ab155c2bf072");

// Generates the little endian representation of a GUID variable
// name.
pub fn guid_to_le_bytes(guid: &Uuid) -> Vec<u8> {
    let mut guid_bytes_le: Vec<u8> = guid.as_bytes().to_vec();

    guid_bytes_le[0..4].reverse();
    guid_bytes_le[4..6].reverse();
    guid_bytes_le[6..8].reverse();
    // Bytes from 8 on are not reversed
    guid_bytes_le
}

pub fn get_secureboot_state_event(enabled: bool) -> UEFIVariableData {
    UEFIVariableData::new(GUID_GLOBAL_VARIABLE, "SecureBoot", vec![enabled as u8])
}

// Struct representing UEFIVariable data and the events it could measure in
// the TPM
#[derive(Debug)]
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

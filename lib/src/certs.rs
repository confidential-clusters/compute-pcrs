use crate::uefi::{EFI_CERT_TYPE_X509_GUID, guid_to_le_bytes};
use std::fmt;

#[derive(Debug)]
pub struct X509Cert {
    pub issuer: String,
    pub subject: String,
    pub raw: Vec<u8>,
}

impl X509Cert {
    pub fn from_der(data: &[u8]) -> Result<X509Cert, openssl::error::ErrorStack> {
        let cert = openssl::x509::X509::from_der(data)?;
        Ok(X509Cert {
            issuer: cert_issuer(&cert),
            subject: cert_subject(&cert),
            raw: data.to_vec(),
        })
    }
}

#[derive(Clone, Debug)]
pub struct CertDbParsingError {
    string: String,
}

impl CertDbParsingError {
    pub fn new(string: &str) -> CertDbParsingError {
        CertDbParsingError {
            string: string.into(),
        }
    }
}

impl fmt::Display for CertDbParsingError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Error parsing cert db: {}", self.string)
    }
}

/// Tries formatting openssl name entries into the entry format that lief
/// uses for subject and issuer strings.
fn entry_to_string(entry: &openssl::x509::X509NameEntryRef) -> Option<String> {
    // TODO improve the way both object is formatted to str
    let object = format!("{:?}", entry.object());
    let data = entry.data().as_utf8().unwrap();
    // commas inside the entry strings in lief are preceeded by an escape char
    let data_str = std::str::from_utf8(data.as_bytes())
        .unwrap()
        .replace(",", "\\,");
    if object == "countryName" {
        return Some(format!("C={data_str}"));
    } else if object == "stateOrProvinceName" {
        return Some(format!("ST={data_str}"));
    } else if object == "localityName" {
        return Some(format!("L={data_str}"));
    } else if object == "organizationName" {
        return Some(format!("O={data_str}"));
    } else if object == "commonName" {
        return Some(format!("CN={data_str}"));
    } else if object == "organizationalUnitName" {
        return Some(format!("OU={data_str}"));
    }
    None
}

/// Given a openssl X509 certificate, it returns a string representing the cert
/// subject that can be compared to the strings that the lief package uses to
/// represent cert subjects
fn cert_subject(cert: &openssl::x509::X509) -> String {
    cert.subject_name()
        .entries()
        .filter_map(entry_to_string)
        .collect::<Vec<_>>()
        .join(", ")
}

/// Given a openssl X509 certificate, it returns a string representing the cert
/// issuer that can be compared to the strings that the lief package uses to
/// represent cert issuers
fn cert_issuer(cert: &openssl::x509::X509) -> String {
    cert.issuer_name()
        .entries()
        .filter_map(entry_to_string)
        .collect::<Vec<_>>()
        .join(", ")
}

/// Finds the certificates that UEFI db contains given its raw representation
/// Returns X509 structures and their raw representation
fn get_db_certs_raw(
    data: &[u8],
) -> Result<Vec<(openssl::x509::X509, Vec<u8>)>, CertDbParsingError> {
    let mut certs = Vec::new();
    let mut offset = 0;

    if data.is_empty() {
        return Ok(vec![]);
    }

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
            return Err(CertDbParsingError::new("Invalid list size"));
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

    Ok(certs)
}

// Given the raw representation of a certificate db, it returns a vector
// containing X509Cert representations of its contents
pub fn get_db_certs(data: &[u8]) -> Result<Vec<X509Cert>, CertDbParsingError> {
    Ok(get_db_certs_raw(data)?
        .iter()
        .map(|(c, r)| X509Cert {
            subject: cert_subject(c),
            issuer: cert_issuer(c),
            raw: r.clone(),
        })
        .collect())
}

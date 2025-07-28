use lief::generic::Section;
use std::fs::File;
use std::os::unix::fs::FileExt;

const SHIM_VENDOR_CERT_SECTION: &str = ".vendor_cert";

pub struct PeFile {
    image: lief::pe::Binary,
    path: String,
    vmlinuz: bool,
}

impl PeFile {
    pub fn load_from_file(path: &str, vmlinuz: bool) -> Option<PeFile> {
        Some(PeFile {
            image: lief::pe::Binary::parse(path)?,
            path: path.into(),
            vmlinuz,
        })
    }

    pub fn image(&self) -> &lief::pe::Binary {
        &self.image
    }

    pub fn authenticode(&self) -> Vec<u8> {
        if self.vmlinuz {
            return self.authenticode_vmlinuz();
        }

        self.image.authentihash(lief::pe::Algorithms::SHA_256)
    }

    fn authenticode_vmlinuz(&self) -> Vec<u8> {
        if let Some(signature) = self.signatures().next() {
            return signature.content_info().digest();
        }
        vec![]
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

    pub fn section(&self, name: &str) -> Option<Vec<u8>> {
        for section in self.image.sections() {
            if self.long_section_name(section.name()) == name {
                return Some(section.content().to_vec());
            }
        }
        None
    }

    fn get_vendor_cert_auth(&self) -> Option<Vec<u8>> {
        let vendor_cert_raw = self.section(SHIM_VENDOR_CERT_SECTION)?;
        // 4 u32 header consisting of:
        //  - auth_size
        //  - deauth_size
        //  - auth_offset
        //  - deauth_offset
        let auth_size = u32::from_le_bytes(
            vendor_cert_raw[0..4]
                .try_into()
                .expect("Badly hardcoded section size"),
        ) as usize;
        let auth_offset = u32::from_le_bytes(
            vendor_cert_raw[8..12]
                .try_into()
                .expect("Badly hardcoded section size"),
        ) as usize;
        Some(vendor_cert_raw[auth_offset..auth_offset + auth_size].to_vec())
    }

    /// The pe file can carry a .vendor_cert section, in which it could store
    /// certificates in db format. Just as shim could do.
    /// This function parses the db and returns the certificates
    pub fn vendor_db(&self) -> Vec<crate::certs::X509Cert> {
        match self.get_vendor_cert_auth() {
            None => vec![],
            Some(certs) => crate::certs::get_db_certs(&certs).unwrap_or_default(),
        }
    }

    /// The .vendor_cert section of the pe file could also store just a
    /// certificate. Just as shim could do.
    /// This function parses the certificate and returns a vector that holds it
    pub fn vendor_cert(&self) -> Vec<crate::certs::X509Cert> {
        if let Some(vendor_cert_auth) = self.get_vendor_cert_auth() {
            return match crate::certs::X509Cert::from_der(&vendor_cert_auth) {
                Ok(cert) => vec![cert],
                Err(_) => vec![],
            };
        }
        vec![]
    }

    pub fn signatures(&self) -> lief::pe::signature::Signatures {
        self.image.signatures()
    }

    pub fn find_cert_in_db(&self, db: &Vec<crate::certs::X509Cert>) -> Option<Vec<u8>> {
        for signature in self.signatures() {
            for certificate in signature.certificates() {
                let file_cert_subject = certificate.subject();
                let file_cert_issuer = certificate.issuer();
                for cert in db {
                    if cert.subject == file_cert_subject || cert.subject == file_cert_issuer {
                        return Some(cert.raw.clone());
                    }
                }
            }
        }
        None
    }
}

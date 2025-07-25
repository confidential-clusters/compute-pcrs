use super::UEFIVariableData;

pub trait SecureBootdbLoader {
    /// Method that returns the raw data of the secure boot db
    fn secureboot_db(&self) -> Vec<u8>;
}

pub trait SecureBootVarLoader: Iterator<Item = UEFIVariableData> + SecureBootdbLoader {}

pub fn collect_secure_boot_hashes<L: SecureBootVarLoader>(loader: L) -> Vec<(String, Vec<u8>)> {
    loader
        .map(|var| ("EV_EFI_VARIABLE_DRIVER_CONFIG".into(), var.hash()))
        .collect()
}

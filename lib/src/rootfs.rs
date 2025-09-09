use crate::esp;
use crate::linux::load_vmlinuz;
use crate::pefile;
use std::io;
use std::path;
use std::result::Result;

const RELATIVE_KERNELS_PATH: &str = "usr/lib/modules/";
const RELATIVE_ESP_PATH: &str = "usr/lib/bootupd/updates/";

pub struct RootFSTree {
    esp: esp::Esp,
    kernels_path: String,
}

impl RootFSTree {
    pub fn new(rootfs_path: &str) -> io::Result<RootFSTree> {
        let rootfs_path = path::absolute(rootfs_path)?;
        let kernels_path = rootfs_path.join(RELATIVE_KERNELS_PATH);
        let esp_path = rootfs_path.join(RELATIVE_ESP_PATH);
        Ok(RootFSTree {
            esp: esp::Esp::new(esp_path.to_str().unwrap())?,
            kernels_path: kernels_path.to_str().unwrap().into(),
        })
    }

    pub fn shim(&self) -> pefile::PeFile {
        self.esp.shim()
    }

    pub fn grub(&self) -> pefile::PeFile {
        self.esp.grub()
    }

    pub fn vmlinuz(&self) -> Result<pefile::PeFile, Box<dyn std::error::Error>> {
        load_vmlinuz(&self.kernels_path)
    }
}

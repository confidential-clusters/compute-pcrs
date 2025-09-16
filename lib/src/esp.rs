// SPDX-FileCopyrightText: Timothée Ravier <tim@siosm.fr>
// SPDX-FileCopyrightText: Beñat Gartzia Arruabarrena <bgartzia@redhat.com>
//
// SPDX-License-Identifier: MIT

use crate::pefile;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

#[derive(Debug)]
pub struct Esp {
    shim: PathBuf,
    grub: PathBuf,
}

const ESP_VENDOR_NAMES: [&str; 2] = ["redhat", "fedora"];

fn esp_vendor_path(esp_root_path: &Path) -> io::Result<PathBuf> {
    for vendor in ESP_VENDOR_NAMES {
        let vendor_path = esp_root_path.join(format!("EFI/{vendor}"));
        match fs::metadata(&vendor_path) {
            Err(_) => {}
            Ok(metadata) => {
                if metadata.is_dir() {
                    return Ok(vendor_path);
                }
            }
        }
    }
    Err(io::Error::new(
        io::ErrorKind::NotFound,
        String::from("Unknown ESP tree format"),
    ))
}

fn bin_path_from_esp_vendor(esp_vendor_path: &Path, bin_name: &str) -> io::Result<PathBuf> {
    let bin_path = esp_vendor_path.join(bin_name);
    let metadata = fs::metadata(&bin_path)?;
    if metadata.is_file() {
        return Ok(bin_path);
    }
    Err(io::Error::new(
        io::ErrorKind::IsADirectory,
        bin_path.to_string_lossy(),
    ))
}

impl Esp {
    pub fn new(path: &str) -> io::Result<Esp> {
        let path_pb = PathBuf::from(path);
        if !fs::metadata(path)?.is_dir() {
            return Err(io::Error::new(io::ErrorKind::NotADirectory, path));
        }

        let esp_vendor_path = esp_vendor_path(&path_pb)?;

        Ok(Esp {
            grub: bin_path_from_esp_vendor(&esp_vendor_path, "shimx64.efi")?,
            shim: bin_path_from_esp_vendor(&esp_vendor_path, "grubx64.efi")?,
        })
    }

    /// Tries loading the shim binary
    pub fn shim(&self) -> pefile::PeFile {
        pefile::PeFile::load_from_file(&self.grub.to_string_lossy(), false)
            .expect("Can't open shim binary")
    }

    /// Tries loading the grub binary
    pub fn grub(&self) -> pefile::PeFile {
        pefile::PeFile::load_from_file(&self.shim.to_string_lossy(), false)
            .expect("Can't open grub binary")
    }
}

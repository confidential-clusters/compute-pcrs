// SPDX-FileCopyrightText: Timothée Ravier <tim@siosm.fr>
// SPDX-FileCopyrightText: Beñat Gartzia Arruabarrena <bgartzia@redhat.com>
//
// SPDX-License-Identifier: MIT

use std::io;
use std::path;

const RELATIVE_KERNELS_PATH: &str = "usr/lib/modules/";
const RELATIVE_ESP_PATH: &str = "usr/lib/bootupd/updates/";

pub struct RootFSTree {
    esp_path: String,
    kernels_path: String,
}

impl RootFSTree {
    pub fn new(rootfs_path: &str) -> io::Result<RootFSTree> {
        let rootfs_path = path::absolute(rootfs_path)?;
        let kernels_path = rootfs_path.join(RELATIVE_KERNELS_PATH);
        let esp_path = rootfs_path.join(RELATIVE_ESP_PATH);
        Ok(RootFSTree {
            esp_path: esp_path.to_str().unwrap().into(),
            kernels_path: kernels_path.to_str().unwrap().into(),
        })
    }

    pub fn esp(&self) -> &str {
        self.esp_path.as_str()
    }

    pub fn vmlinuz(&self) -> &str {
        self.kernels_path.as_str()
    }
}

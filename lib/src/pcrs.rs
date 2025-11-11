// SPDX-FileCopyrightText: Timothée Ravier <tim@siosm.fr>
// SPDX-FileCopyrightText: Beñat Gartzia Arruabarrena <bgartzia@redhat.com>
//
// SPDX-License-Identifier: MIT

use crate::tpmevents::TPMEvent;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use sha2::{Digest, Sha256};

const PCR_INIT_VALUE: [u8; 32] = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
];

#[cfg(test)]
mod tests;

#[serde_as]
#[derive(Clone, Serialize, Deserialize)]
#[cfg_attr(test, derive(PartialEq, Debug))]
pub struct Part {
    pub name: String,
    #[serde_as(as = "serde_with::hex::Hex")]
    pub hash: Vec<u8>,
}

#[serde_as]
#[derive(Clone, Serialize, Deserialize)]
#[cfg_attr(test, derive(PartialEq, Debug))]
pub struct Pcr {
    pub id: u64,
    #[serde_as(as = "serde_with::hex::Hex")]
    pub value: Vec<u8>,
    pub parts: Vec<Part>,
}

impl From<&TPMEvent> for Part {
    fn from(event: &TPMEvent) -> Part {
        Part {
            name: event.name.clone(),
            hash: event.hash.clone(),
        }
    }
}

impl Pcr {
    pub fn compile_from(events: &Vec<TPMEvent>) -> Pcr {
        let mut result = PCR_INIT_VALUE.to_vec();

        for event in events {
            let mut hasher = Sha256::new();
            hasher.update(result);
            hasher.update(event.hash.clone());
            result = hasher.finalize().to_vec();
        }

        Pcr {
            id: events[0].pcr.into(),
            value: result,
            parts: events.iter().map(|e| e.into()).collect(),
        }
    }
}

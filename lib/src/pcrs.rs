// SPDX-FileCopyrightText: Timothée Ravier <tim@siosm.fr>
// SPDX-FileCopyrightText: Beñat Gartzia Arruabarrena <bgartzia@redhat.com>
//
// SPDX-License-Identifier: MIT

use serde::{Deserialize, Serialize};
use serde_with::serde_as;

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

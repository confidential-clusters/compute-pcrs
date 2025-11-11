// SPDX-FileCopyrightText: Beñat Gartzia Arruabarrena <bgartzia@redhat.com>
//
// SPDX-License-Identifier: MIT
use super::*;
use crate::tpmevents::{TPMEvent, TPMEventID};

use std::collections::HashMap;

#[test]
fn test_tpm_event_id_hashmap() {
    let foo = TPMEvent {
        name: "FOO".into(),
        pcr: 0x00,
        hash: vec![0, 0, 0],
        id: TPMEventID::PcrRootNodeEvent,
    };
    let bar = TPMEvent {
        name: "BAR".into(),
        pcr: 0xFF,
        hash: vec![4, 5, 6],
        id: TPMEventID::Pcr11Sbat,
    };
    let foobar = TPMEvent {
        name: "FOOBAR".into(),
        pcr: 0xe8,
        hash: vec![1, 2, 3, 4, 5],
        id: TPMEventID::Pcr11UnameContent,
    };
    let events = vec![foo.clone(), bar.clone(), foobar.clone()];

    let res = tpm_event_id_hashmap(&events);
    assert_eq!(
        res,
        HashMap::from([
            (TPMEventID::PcrRootNodeEvent, foo),
            (TPMEventID::Pcr11Sbat, bar),
            (TPMEventID::Pcr11UnameContent, foobar),
        ])
    );
}

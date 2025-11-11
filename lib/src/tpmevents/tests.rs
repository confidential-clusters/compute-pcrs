// SPDX-FileCopyrightText: Beñat Gartzia Arruabarrena <bgartzia@redhat.com>
//
// SPDX-License-Identifier: MIT
use super::*;

#[test]
fn test_tpmevevent_next_first() {
    let event = TPMEventID::PcrRootNodeEvent;
    assert_eq!(event.next(), Some(TPMEventID::Pcr4EfiCall));
}

#[test]
fn test_tpmevevent_next_last() {
    let event = TPMEventID::Pcr14MokListTrusted;
    assert_eq!(event.next(), None);
}

#[test]
fn test_tpmevevent_next_some() {
    let event = TPMEventID::Pcr4Separator;
    assert_eq!(event.next(), Some(TPMEventID::Pcr4Shim));
}

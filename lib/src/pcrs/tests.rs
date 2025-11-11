// SPDX-FileCopyrightText: Beñat Gartzia Arruabarrena <bgartzia@redhat.com>
//
// SPDX-License-Identifier: MIT

use super::*;
use crate::tpmevents::{TPMEvent, TPMEventID};

#[test]
fn test_part_serialization() {
    let input = Part {
        name: "foo".into(),
        hash: vec![1, 0, 2, 3, 255],
    };
    let expected = String::from("{\"name\":\"foo\",\"hash\":\"01000203ff\"}");

    assert_eq!(serde_json::to_string(&input).unwrap(), expected);
}

#[test]
fn test_part_deserialization() {
    let input = String::from("{\"name\":\"bar\",\"hash\":\"0f0300\"}");
    let expected = Part {
        name: "bar".into(),
        hash: vec![15, 3, 0],
    };
    let deserialized: Part = serde_json::from_str(&input).unwrap();

    assert_eq!(deserialized, expected);
}

#[test]
fn test_pcr_serialization() {
    let input = Pcr {
        id: 123,
        value: vec![0, 0, 0, 0, 0, 0, 0, 253],
        parts: vec![Part {
            name: "foo".into(),
            hash: vec![1, 0, 2, 3, 255],
        }],
    };
    let expected = String::from(
        "{\"id\":123,\"value\":\"00000000000000fd\",\"parts\":[{\"name\":\"foo\",\"hash\":\"01000203ff\"}]}",
    );

    assert_eq!(serde_json::to_string(&input).unwrap(), expected);
}

#[test]
fn test_pcr_deserialization() {
    let expected = Pcr {
        id: 0,
        value: vec![0, 0, 0, 0, 0, 0, 0, 240],
        parts: vec![Part {
            name: "foo".into(),
            hash: vec![1, 0, 2, 3, 255],
        }],
    };

    let deserialized: Pcr = serde_json::from_str(
        "{\"id\":0,\"value\":\"00000000000000f0\",\"parts\":[{\"name\":\"foo\",\"hash\":\"01000203ff\"}]}"
    ).unwrap();

    assert_eq!(deserialized, expected);
}

#[test]
fn test_part_from_tpmevent() {
    let input = TPMEvent {
        name: "FOOBAR".into(),
        pcr: 255,
        hash: vec![0, 1, 2, 3, 4, 5, 6, 7, 8],
        id: TPMEventID::Pcr4EfiCall,
    };
    let expected = Part {
        name: "FOOBAR".into(),
        hash: vec![0, 1, 2, 3, 4, 5, 6, 7, 8],
    };

    let res: Part = (&input).into();

    assert_eq!(res, expected);
}

#[test]
fn test_pcr_compilation_from_tpmevents() {
    let input = vec![
        TPMEvent {
            name: "FOOBAR".into(),
            pcr: 255,
            hash: vec![
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0,
            ],
            id: TPMEventID::Pcr4EfiCall,
        },
        TPMEvent {
            name: "BARFOO".into(),
            pcr: 255,
            hash: vec![
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 1,
            ],
            // Having a pcr7 event here does not make sense if the previous one
            // was pcr4, but id should be sane at this point in the execution
            id: TPMEventID::Pcr7SecureBoot,
        },
    ];
    let expected = Pcr {
        id: 255,
        value: vec![
            65, 62, 10, 52, 9, 169, 42, 229, 47, 108, 155, 208, 62, 239, 192, 64, 254, 216, 40,
            213, 49, 150, 204, 191, 240, 146, 157, 233, 235, 71, 46, 91,
        ],
        parts: vec![
            Part {
                name: "FOOBAR".into(),
                hash: vec![
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0,
                ],
            },
            Part {
                name: "BARFOO".into(),
                hash: vec![
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 1,
                ],
            },
        ],
    };

    let res = Pcr::compile_from(&input);

    assert_eq!(res, expected);
}

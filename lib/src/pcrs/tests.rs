// SPDX-FileCopyrightText: Beñat Gartzia Arruabarrena <bgartzia@redhat.com>
//
// SPDX-License-Identifier: MIT

use super::*;

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

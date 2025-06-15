use anyhow::{Ok, Result};
use hex_literal::hex;
use lief::generic::Section;
use sha2::{Sha256, Digest};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
struct Part {
    name: String,
    hash: String,
}

#[derive(Serialize, Deserialize)]
struct PCR {
    id: u64, 
    value: String,
    parts: Vec<Part>,
}

#[derive(Serialize, Deserialize)]
struct Output {
    pcrs: Vec<PCR>,
}

fn compute_pcr4() {
    let ev_efi_action_hash: Vec<u8> = Sha256::digest(b"Calling EFI Application from Boot Option").to_vec();
    let ev_separator_hash: Vec<u8> = Sha256::digest(hex::decode("00000000").unwrap()).to_vec();

    let bins = vec![
        "shim.efi",
        "grubx64.efi",
        "a9ea995b29cda6783b676e2ec2666d8813882b604625389428ece4eee074e742.efi",
    ];

    let mut hashes: Vec<(String, Vec<u8>)> = vec![];
    hashes.push(("EV_EFI_ACTION".into(), ev_efi_action_hash));
    hashes.push(("EV_SEPARATOR".into(), ev_separator_hash));

    let mut bin_hashes: Vec<(String, Vec<u8>)> = bins.iter().map(|b| {
        let pe: lief::pe::Binary = lief::pe::Binary::parse(&format!("./test/{}", b)).unwrap();
        ((*b).into(), pe.authentihash(lief::pe::Algorithms::SHA_256))
    }).collect();
    hashes.append(&mut bin_hashes);

    // println!("{:?}", ev_efi_action_hash);
    // println!("{:?}", ev_separator_hash);
    // hashes.iter().for_each(|h| {
    //     println!("{:?}", h);
    // });

    // Start with 0
    let mut result = hex::decode("0000000000000000000000000000000000000000000000000000000000000000").unwrap().to_vec();

    for (_p, h) in &hashes{
        let mut hasher = Sha256::new();
        hasher.update(result);
        hasher.update(h);
        result = hasher.finalize().to_vec();
    }

    // println!("{}", hex::encode(result));

    assert_eq!(result[..], hex!("1714C36BF81EF84ECB056D6BA815DCC8CA889074AFB69D621F1C4D8FA03B23F0"));

    let pcr4 = PCR{
        id: 4,
        value:  hex::encode(result),
        parts: hashes.iter().map(|(p, h)| {
            Part {
                name: p.to_string(),
                hash: hex::encode(h)
            }
        }).collect(),
    };

    println!("{}", serde_json::to_string_pretty(&pcr4).unwrap());
}

fn compute_pcr11() {
    let sections: Vec<&str> = vec![
        ".linux",
        ".osrel",
        ".cmdline",
        ".initrd",
        ".uname",
        ".sbat",
    ];

    let uki = "a9ea995b29cda6783b676e2ec2666d8813882b604625389428ece4eee074e742.efi";
    let pe: lief::pe::Binary = lief::pe::Binary::parse(&format!("./test/{}", uki)).unwrap();
    let hashes = sections.iter().for_each(|s| {
        let section = pe.section_by_name(s).unwrap();
        println!("{}", hex::encode(Sha256::digest(format!("{}\0", s)).to_vec()));
        println!("{}", hex::encode(Sha256::digest(section.content()).to_vec()));
    });

    // let ev_efi_action_hash: Vec<u8> = Sha256::digest(sections[0]).to_vec();
    // // let ev_separator_hash: Vec<u8> = Sha256::digest(hex::decode("00000000").unwrap()).to_vec();

    // let bins = vec![
    //     "./test/shim.efi",
    //     "./test/grubx64.efi",
    //     "./test/a9ea995b29cda6783b676e2ec2666d8813882b604625389428ece4eee074e742.efi",
    // ];

    // let mut hashes: Vec<Vec<u8>> = vec![];
    // hashes.push(ev_efi_action_hash);
    // hashes.push(ev_separator_hash);

    // let mut bin_hashes: Vec<Vec<u8>> = bins.iter().map(|b| {
    //     let pe: lief::pe::Binary = lief::pe::Binary::parse(b).unwrap();
    //     pe.authentihash(lief::pe::Algorithms::SHA_256)
    // }).collect();
    // hashes.append(&mut bin_hashes);

    // // println!("{:?}", ev_efi_action_hash);
    // // println!("{:?}", ev_separator_hash);
    // // hashes.iter().for_each(|h| {
    // //     println!("{:?}", h);
    // // });

    // // Start with 0
    // let mut result = hex::decode("0000000000000000000000000000000000000000000000000000000000000000").unwrap().to_vec();

    // for h in &hashes{
    //     let mut hasher = Sha256::new();
    //     hasher.update(result);
    //     hasher.update(h);
    //     result = hasher.finalize().to_vec();
    // }

    // // println!("{}", hex::encode(result));

    // assert_eq!(result[..], hex!("1714C36BF81EF84ECB056D6BA815DCC8CA889074AFB69D621F1C4D8FA03B23F0"));

    // let pcr4 = PCR{
    //     id: 4,
    //     value:  hex::encode(result),
    //     parts: hashes.iter().map(|h| {
    //         hex::encode(h)
    //     }).collect(),
    // };

    // println!("{}", serde_json::to_string_pretty(&pcr4).unwrap());
}

fn main() -> Result<()> {

    // compute_pcr4();

    compute_pcr11();

    Ok(())
}

use crate::shim::{Shim, get_sbat_var_original_uefivar};
use crate::uefi::efivars::{
    EFIVarsLoader, SECURE_BOOT_ATTR_HEADER_LENGTH, get_secure_boot_targets,
};
use anyhow::{Ok, Result};
use hex_literal::hex;
use lief::generic::Section;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub mod shim;
pub mod uefi;

#[derive(Serialize, Deserialize)]
struct Part {
    name: String,
    hash: String,
}

#[derive(Serialize, Deserialize)]
struct Pcr {
    id: u64,
    value: String,
    parts: Vec<Part>,
}

#[derive(Serialize, Deserialize)]
struct Output {
    pcrs: Vec<Pcr>,
}

fn compute_pcr4() -> Pcr {
    let ev_efi_action_hash: Vec<u8> =
        Sha256::digest(b"Calling EFI Application from Boot Option").to_vec();
    let ev_separator_hash: Vec<u8> = Sha256::digest(hex::decode("00000000").unwrap()).to_vec();

    let bins = [
        "shim.efi",
        "grubx64.efi",
        "a9ea995b29cda6783b676e2ec2666d8813882b604625389428ece4eee074e742.efi",
    ];

    let mut hashes: Vec<(String, Vec<u8>)> = vec![];
    hashes.push(("EV_EFI_ACTION".into(), ev_efi_action_hash));
    hashes.push(("EV_SEPARATOR".into(), ev_separator_hash));

    let mut bin_hashes: Vec<(String, Vec<u8>)> = bins
        .iter()
        .map(|b| {
            let pe: lief::pe::Binary = lief::pe::Binary::parse(&format!("./test/{b}")).unwrap();
            ((*b).into(), pe.authentihash(lief::pe::Algorithms::SHA_256))
        })
        .collect();
    hashes.append(&mut bin_hashes);

    // println!("{:?}", ev_efi_action_hash);
    // println!("{:?}", ev_separator_hash);
    // hashes.iter().for_each(|h| {
    //     println!("{:?}", h);
    // });

    // Start with 0
    let mut result =
        hex::decode("0000000000000000000000000000000000000000000000000000000000000000")
            .unwrap()
            .to_vec();

    for (_p, h) in &hashes {
        let mut hasher = Sha256::new();
        hasher.update(result);
        hasher.update(h);
        result = hasher.finalize().to_vec();
    }

    // println!("{}", hex::encode(result));

    assert_eq!(
        result[..],
        hex!("1714C36BF81EF84ECB056D6BA815DCC8CA889074AFB69D621F1C4D8FA03B23F0")
    );

    let pcr4 = Pcr {
        id: 4,
        value: hex::encode(result),
        parts: hashes
            .iter()
            .map(|(p, h)| Part {
                name: p.to_string(),
                hash: hex::encode(h),
            })
            .collect(),
    };

    // println!("{}", serde_json::to_string_pretty(&pcr4).unwrap());

    pcr4
}

fn compute_pcr11() -> Pcr {
    let sections: Vec<&str> = vec![".linux", ".osrel", ".cmdline", ".initrd", ".uname", ".sbat"];

    let uki = "a9ea995b29cda6783b676e2ec2666d8813882b604625389428ece4eee074e742.efi";
    let pe: lief::pe::Binary = lief::pe::Binary::parse(&format!("./test/{uki}")).unwrap();
    let mut hashes: Vec<(String, Vec<u8>)> = vec![];
    sections.iter().for_each(|s| {
        let section = pe.section_by_name(s).unwrap();
        hashes.push(((*s).into(), Sha256::digest(format!("{s}\0")).to_vec()));
        hashes.push(((*s).into(), Sha256::digest(section.content()).to_vec()));
    });

    // Start with 0
    let mut result =
        hex::decode("0000000000000000000000000000000000000000000000000000000000000000")
            .unwrap()
            .to_vec();

    for (_s, h) in &hashes {
        let mut hasher = Sha256::new();
        hasher.update(result);
        hasher.update(h);
        result = hasher.finalize().to_vec();
    }

    // println!("{}", hex::encode(&result));

    let pcr11 = Pcr {
        id: 11,
        value: hex::encode(result),
        parts: hashes
            .iter()
            .map(|(s, h)| Part {
                name: s.into(),
                hash: hex::encode(h),
            })
            .collect(),
    };

    // println!("{}", serde_json::to_string_pretty(&pcr11).unwrap());

    pcr11
}

/// PCR 7 contains the digests of the variables defining the Secure Boot
/// state. It's extended by the following events:
///    - EV_EFI_VARIABLE_DRIVER_CONFIG: SecureBoot
///    - EV_EFI_VARIABLE_DRIVER_CONFIG: PK
///    - EV_EFI_VARIABLE_DRIVER_CONFIG: KEK
///    - EV_EFI_VARIABLE_DRIVER_CONFIG: db
///    - EV_EFI_VARIABLE_DRIVER_CONFIG: dbx
///    - EV_SEPARATOR
///    - EV_EFI_VARIABLE_AUTHORITY: db (TODO)
///    - EV_EFI_VARIABLE_AUTHORITY: SbatLevel
///    - EV_EFI_VARIABLE_AUTHORITY: MokListRT (TODO)
///
/// EFI vars are needed to compute pcr7.
/// EFI vars can be loaded from
///     - efivars
///
fn compute_pcr7() -> Pcr {
    let sb_var_loader = EFIVarsLoader::new(
        "test/efivars/qemu-ovmf/fcos-42",
        SECURE_BOOT_ATTR_HEADER_LENGTH,
        get_secure_boot_targets(),
    );
    let mut hashes: Vec<(String, Vec<u8>)> = sb_var_loader
        .map(|var| ("EV_EFI_VARIABLE_DRIVER_CONFIG".into(), var.hash()))
        .collect();

    hashes.push((
        "EV_SEPARATOR".into(),
        Sha256::digest(hex::decode("00000000").unwrap()).to_vec(),
    ));

    // TODO: parametrize path
    let shim_bin = Shim::load_from_file("./test/shimx64.efi");
    let sbatlevel = shim_bin.get_sbatlevel_uefivar();
    match sbatlevel {
        None => hashes.push((
            "EV_EFI_VARIABLE_AUTHORITY".into(),
            get_sbat_var_original_uefivar().hash(),
        )),
        Some(level) => hashes.push(("EV_EFI_VARIABLE_AUTHORITY".into(), level.hash())),
    }

    let mut result =
        hex::decode("0000000000000000000000000000000000000000000000000000000000000000")
            .unwrap()
            .to_vec();

    for (_s, h) in &hashes {
        let mut hasher = Sha256::new();
        hasher.update(result);
        hasher.update(h);
        result = hasher.finalize().to_vec();
    }

    let pcr7 = Pcr {
        id: 7,
        value: hex::encode(result),
        parts: hashes
            .iter()
            .map(|(s, h)| Part {
                name: s.into(),
                hash: hex::encode(h),
            })
            .collect(),
    };
    pcr7
}

fn main() -> Result<()> {
    let pcrs = vec![compute_pcr4(), compute_pcr7(), compute_pcr11()];
    println!(
        "{}",
        serde_json::to_string_pretty(&Output { pcrs }).unwrap()
    );

    Ok(())
}

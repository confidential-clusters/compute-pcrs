use anyhow::{Ok, Result};
use hex_literal::hex;
use sha2::{Sha256, Digest};

fn main() -> Result<()> {
    let prc_zero = hex::decode("0000000000000000000000000000000000000000000000000000000000000000").unwrap();

    let ev_efi_action_hash = Sha256::digest(b"Calling EFI Application from Boot Option");
    let ev_separator_hash = Sha256::digest(hex::decode("00000000").unwrap());

    let bins = vec![
        "./test/shim.efi",
        "./test/grubx64.efi",
        "./test/a9ea995b29cda6783b676e2ec2666d8813882b604625389428ece4eee074e742.efi",
    ];

    let hashes: Vec<Vec<u8>> = bins.iter().map(|b| {
        let pe: lief::pe::Binary = lief::pe::Binary::parse(b).unwrap();
        pe.authentihash(lief::pe::Algorithms::SHA_256)
    }).collect();

    // println!("{:?}", ev_efi_action_hash);
    // println!("{:?}", ev_separator_hash);
    hashes.iter().for_each(|h| {
        // println!("{:?}", h);
    });

    let hash: [u8; 32] = Sha256::digest(b"hello world").into();
    assert_eq!(hash, hex!("b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"));

    let mut hasher = Sha256::new();
    hasher.update(prc_zero);
    hasher.update(ev_efi_action_hash);
    let mut result = hasher.finalize();

    let mut hasher = Sha256::new();
    hasher.update(result);
    hasher.update(ev_separator_hash);
    result = hasher.finalize();

    for h in hashes{
        let mut hasher = Sha256::new();
        hasher.update(result);
        hasher.update(h);
        result = hasher.finalize();
    }

    println!("{}", hex::encode(result));

    assert_eq!(result[..], hex!("1714C36BF81EF84ECB056D6BA815DCC8CA889074AFB69D621F1C4D8FA03B23F0"));

    Ok(())
}

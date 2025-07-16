use crate::uefi::{GUID_SHIM_LOCK, UEFIVariableData};

pub const SHIM_SBATLEVEL_SECTION: &str = ".sbatlevel";
const SBAT_VAR_ORIGINAL: &str = "sbat,1,2021030218\n";

pub enum SbatLevelPolicyType {
    PREVIOUS,
    LATEST,
}

// Given the raw .sbatlevel section data, it returns the .sbatlevel data of the
// target sbatlevel policy, which can be previous or latest.
//
// The .sbatlevel section contains a 3*u32 header struct consisting of:
//  - version
//  - previous .sbatlevel policy section offset
//  - latest .sbatlevel policy section offset
fn get_sbatlevel_section(sbatlevel_raw: &[u8], sbatlevel_policy: &SbatLevelPolicyType) -> Vec<u8> {
    let raw_len = sbatlevel_raw.len();
    assert!(raw_len > 12, "Unknown sbatlevel data format: too short");

    let policy_offset: usize = match sbatlevel_policy {
        SbatLevelPolicyType::PREVIOUS => u32::from_le_bytes(
            sbatlevel_raw[4..8]
                .try_into()
                .expect("Badly hardcoded section size"),
        ) as usize,
        SbatLevelPolicyType::LATEST => u32::from_le_bytes(
            sbatlevel_raw[8..12]
                .try_into()
                .expect("Badly hardcoded section size"),
        ) as usize,
    } + 4;
    assert!(
        raw_len > policy_offset + 1,
        "Unknown sbatlevel data format: too short"
    );

    let mut policy_end: usize = policy_offset;
    loop {
        let next_char = sbatlevel_raw[policy_end];
        if next_char == 0 {
            break;
        }
        policy_end += 1;
    }

    sbatlevel_raw[policy_offset..policy_end].to_vec()
}

pub fn get_sbat_var_original_uefivar() -> UEFIVariableData {
    UEFIVariableData::new(GUID_SHIM_LOCK, "SbatLevel", SBAT_VAR_ORIGINAL.into())
}

/// Given the raw data of the .sbatlevel section, and the policy type, it
/// process it and returns a UEFIVariableData structure.
pub fn get_sbatlevel_uefivar(
    sbatlevel_raw: &[u8],
    sbatlevel_policy: &SbatLevelPolicyType,
) -> UEFIVariableData {
    UEFIVariableData::new(
        GUID_SHIM_LOCK,
        "SbatLevel",
        get_sbatlevel_section(sbatlevel_raw, sbatlevel_policy),
    )
}

use crate::pefile::PeFile;
use std::io;
use std::result::Result;

/// Given a glob pattern find and load a vmlinuz image candidate
pub fn load_vmlinuz(linux_path: &str) -> Result<PeFile, Box<dyn std::error::Error>> {
    // Given a directory path, it will look under it for vmlinuz images
    let glob_pattern = if linux_path.ends_with("/") {
        format!("{linux_path}*/vmlinuz")
    } else {
        format!("{linux_path}/*/vmlinuz")
    };
    // TODO: At the moment just the first found path will be returned.
    // The logic should be improved to return the latest one, or an iterator
    // so we could work on all the found vmlinuz images instead
    for path in glob::glob(&glob_pattern)?.filter_map(Result::ok) {
        if let Some(bin) = PeFile::load_from_file(&path.to_string_lossy(), true) {
            return Ok(bin);
        }
    }
    Err(Box::new(io::Error::new(
        io::ErrorKind::NotFound,
        String::from("vmlinuz not found"),
    )))
}

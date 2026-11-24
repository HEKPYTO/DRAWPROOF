use std::io::Read;
use std::path::Path;

use crate::error::{Result, field};

pub const MAX_BUNDLE_BYTES: u64 = 64 * 1024 * 1024;
pub const MAX_MANIFEST_BYTES: u64 = 64 * 1024 * 1024;
pub const MAX_DOCUMENT_BYTES: u64 = 4 * 1024;

pub fn read_capped(path: &Path, limit: u64, field_name: &str) -> Result<Vec<u8>> {
    let file = std::fs::File::open(path)
        .map_err(|error| field(field_name, format!("{}: {error}", path.display())))?;
    let mut body = Vec::new();
    file.take(limit + 1)
        .read_to_end(&mut body)
        .map_err(|error| field(field_name, format!("{}: {error}", path.display())))?;
    if body.len() as u64 > limit {
        return Err(field(
            field_name,
            format!("{} exceeds {limit} bytes", path.display()),
        ));
    }
    Ok(body)
}

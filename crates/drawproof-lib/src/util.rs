use sha2::{Digest, Sha256};

use crate::error::{Result, field};

pub(crate) const MAX_NAME_LEN: usize = 128;
pub(crate) const MAX_ID_LEN: usize = 1024;

pub(crate) fn sha256(parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    for part in parts {
        hasher.update(part);
    }
    hasher.finalize().into()
}

pub(crate) fn fixed<const N: usize>(value: &str, path: &str) -> Result<[u8; N]> {
    let bytes = hex::decode(value).map_err(|_| field(path, "must be valid hex"))?;
    let len = bytes.len();
    bytes
        .try_into()
        .map_err(|_| field(path, format!("expected {N} bytes, got {len}")))
}

pub(crate) fn canonical<const N: usize>(value: &str, path: &str) -> Result<[u8; N]> {
    let bytes = fixed::<N>(value, path)?;
    if hex::encode(bytes) != value {
        return Err(field(path, "must be lowercase canonical hex"));
    }
    Ok(bytes)
}

pub(crate) fn validate_name(value: &str, path: &str) -> Result<()> {
    if value.is_empty() {
        return Err(field(path, "must not be empty"));
    }
    if value.len() > MAX_NAME_LEN {
        return Err(field(path, format!("must be at most {MAX_NAME_LEN} bytes")));
    }
    if value.chars().any(char::is_control) {
        return Err(field(path, "must not contain control characters"));
    }
    Ok(())
}

pub(crate) fn validate_id(value: &str, path: &str) -> Result<()> {
    if value.is_empty() {
        return Err(field(path, "must not be empty"));
    }
    if value.len() > MAX_ID_LEN {
        return Err(field(path, format!("must be at most {MAX_ID_LEN} bytes")));
    }
    if value.chars().any(char::is_control) {
        return Err(field(path, "must not contain control characters"));
    }
    Ok(())
}

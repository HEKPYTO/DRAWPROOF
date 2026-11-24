use std::fs::OpenOptions;
use std::io::Write;
use std::path::Path;

use ed25519_dalek::SigningKey;
use serde::{Deserialize, Serialize};

use crate::error::{Result, field};
use crate::{files, util};

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyFile {
    pub name: String,
    pub secret_key: String,
}

impl KeyFile {
    pub fn signing_key(&self) -> Result<SigningKey> {
        util::validate_name(&self.name, "keyfile.name")?;
        let seed = util::canonical::<32>(&self.secret_key, "keyfile.secret_key")?;
        Ok(SigningKey::from_bytes(&seed))
    }
}

pub fn generate(name: &str) -> Result<KeyFile> {
    util::validate_name(name, "keyfile.name")?;
    let mut seed = [0u8; 32];
    getrandom::fill(&mut seed).map_err(|error| {
        field(
            "keyfile.secret_key",
            format!("randomness source failed: {error}"),
        )
    })?;
    Ok(KeyFile {
        name: name.to_string(),
        secret_key: hex::encode(seed),
    })
}

pub fn write(path: &Path, key: &KeyFile) -> Result<()> {
    key.signing_key()?;
    let data = serde_json::to_vec_pretty(key)?;
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .map_err(|error| field("keyfile", format!("{}: {error}", path.display())))?;
    file.write_all(&data)
        .map_err(|error| field("keyfile", format!("{}: {error}", path.display())))?;
    file.sync_all()
        .map_err(|error| field("keyfile", format!("{}: {error}", path.display())))
}

pub fn load(path: &Path) -> Result<(String, SigningKey)> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(path)
            .map_err(|error| field("keyfile", format!("{}: {error}", path.display())))?
            .permissions()
            .mode();
        if mode & 0o077 != 0 {
            return Err(field(
                "keyfile.permissions",
                format!("{} must not be group or world accessible", path.display()),
            ));
        }
    }
    let data = files::read_capped(path, files::MAX_DOCUMENT_BYTES, "keyfile")?;
    let key: KeyFile = serde_json::from_slice(&data)
        .map_err(|error| field("keyfile", format!("invalid JSON: {error}")))?;
    let signing_key = key.signing_key()?;
    Ok((key.name, signing_key))
}

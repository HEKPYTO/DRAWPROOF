use serde::{Deserialize, Serialize};

use crate::error::{Result, field};
use crate::util;

pub const DOMAIN: &str = "drawproof/v1";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Commitment {
    pub root: String,
    pub n: u64,
    pub k: u64,
    pub round: u64,
    pub nonce: String,
}

impl Commitment {
    pub fn new(root: [u8; 32], n: u64, k: u64, round: u64, nonce: [u8; 32]) -> Self {
        Self {
            root: hex::encode(root),
            n,
            k,
            round,
            nonce: hex::encode(nonce),
        }
    }

    pub fn random_nonce() -> Result<[u8; 32]> {
        let mut nonce = [0u8; 32];
        getrandom::fill(&mut nonce).map_err(|error| {
            field(
                "commitment.nonce",
                format!("randomness source failed: {error}"),
            )
        })?;
        Ok(nonce)
    }

    pub fn validate(&self) -> Result<()> {
        util::canonical::<32>(&self.root, "commitment.root")?;
        util::canonical::<32>(&self.nonce, "commitment.nonce")?;
        if self.n == 0 {
            return Err(field("commitment.n", "must be positive"));
        }
        if self.k == 0 {
            return Err(field("commitment.k", "must be positive"));
        }
        if self.k > self.n {
            return Err(field("commitment.k", "must not exceed n"));
        }
        if self.round == 0 {
            return Err(field("commitment.round", "must be positive"));
        }
        Ok(())
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        self.validate()?;
        Ok(format!(
            "{DOMAIN}\nroot={}\nn={}\nk={}\nround={}\nnonce={}",
            self.root, self.n, self.k, self.round, self.nonce
        )
        .into_bytes())
    }

    pub fn sha256(&self) -> Result<[u8; 32]> {
        Ok(util::sha256(&[&self.canonical_bytes()?]))
    }
}

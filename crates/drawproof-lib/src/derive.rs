use std::collections::HashSet;

use sha2::{Digest, Sha256};

use crate::error::{Result, field};

pub fn indices(randomness: &[u8; 32], root: &[u8; 32], n: u64, k: u64) -> Result<Vec<u64>> {
    if n == 0 {
        return Err(field("derive.n", "must be positive"));
    }
    if k == 0 {
        return Err(field("derive.k", "must be positive"));
    }
    if k > n {
        return Err(field("derive.k", "must not exceed n"));
    }
    let count = usize::try_from(k).map_err(|_| field("derive.k", "does not fit this platform"))?;
    let limit = ((1u128 << 64) / n as u128) * n as u128;
    let mut out = Vec::with_capacity(count);
    let mut seen = HashSet::with_capacity(count);
    let mut counter = 0u64;
    while out.len() < count {
        let mut hasher = Sha256::new();
        hasher.update(b"drawproof/v1");
        hasher.update(randomness);
        hasher.update(root);
        hasher.update(counter.to_be_bytes());
        let digest = hasher.finalize();
        let mut head = [0u8; 8];
        head.copy_from_slice(&digest[..8]);
        let value = u64::from_be_bytes(head) as u128;
        if value < limit {
            let index = (value % n as u128) as u64;
            if seen.insert(index) {
                out.push(index);
            }
        }
        counter = counter
            .checked_add(1)
            .ok_or_else(|| field("derive", "counter exhausted"))?;
    }
    Ok(out)
}

use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::error::{Result, field};
use crate::{files, merkle, util};

const LEAF_DOMAIN: &[u8] = b"drawproof/v1/item";

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Entry {
    pub id: String,
    pub sha256: String,
}

#[derive(Clone, Debug)]
pub struct Manifest {
    pub entries: Vec<Entry>,
    pub root: [u8; 32],
    leaves: Vec<[u8; 32]>,
}

impl Manifest {
    pub fn from_jsonl(bytes: &[u8]) -> Result<Self> {
        let text = std::str::from_utf8(bytes)
            .map_err(|error| field("manifest", format!("not UTF-8: {error}")))?;
        let mut parsed: Vec<(Entry, [u8; 32])> = Vec::new();
        for (line_index, line) in text.lines().enumerate() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            let number = line_index + 1;
            let mut entry: Entry = serde_json::from_str(line).map_err(|error| {
                field(
                    &format!("manifest.line{number}"),
                    format!("invalid JSON: {error}"),
                )
            })?;
            util::validate_id(&entry.id, &format!("manifest.line{number}.id"))?;
            let hash = util::fixed::<32>(&entry.sha256, &format!("manifest.line{number}.sha256"))?;
            entry.sha256 = hex::encode(hash);
            parsed.push((entry, hash));
        }
        if parsed.is_empty() {
            return Err(field("manifest", "has no entries"));
        }
        parsed.sort_by(|left, right| left.0.id.as_bytes().cmp(right.0.id.as_bytes()));
        for pair in parsed.windows(2) {
            if pair[0].0.id == pair[1].0.id {
                return Err(field(
                    "manifest",
                    format!("duplicate id {:?}", pair[0].0.id),
                ));
            }
        }
        let leaves: Vec<[u8; 32]> = parsed
            .iter()
            .map(|(entry, hash)| leaf_hash(&entry.id, hash))
            .collect();
        let root = merkle::root(&leaves);
        let entries = parsed.into_iter().map(|(entry, _)| entry).collect();
        Ok(Self {
            entries,
            root,
            leaves,
        })
    }

    pub fn load(path: &Path) -> Result<Self> {
        let bytes = files::read_capped(path, files::MAX_MANIFEST_BYTES, "manifest")?;
        Self::from_jsonl(&bytes)
    }

    pub fn len(&self) -> u64 {
        self.entries.len() as u64
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn root_hex(&self) -> String {
        hex::encode(self.root)
    }

    pub fn leaf(&self, index: usize) -> [u8; 32] {
        self.leaves[index]
    }

    pub fn proof(&self, index: usize) -> Vec<[u8; 32]> {
        merkle::proof(&self.leaves, index)
    }
}

pub(crate) fn leaf_hash(id: &str, hash: &[u8; 32]) -> [u8; 32] {
    let id_bytes = id.as_bytes();
    let length = (id_bytes.len() as u32).to_be_bytes();
    util::sha256(&[&[0u8][..], LEAF_DOMAIN, &length, id_bytes, hash])
}

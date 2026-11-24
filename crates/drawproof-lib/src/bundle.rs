use std::collections::HashSet;
use std::path::Path;

use drand::{Beacon, VerifiedBeacon};
use serde::{Deserialize, Serialize};

use crate::commitment::Commitment;
use crate::error::{Result, field};
use crate::manifest::{Manifest, leaf_hash};
use crate::{beacon, derive, files, merkle, receipt, util};

pub const VERSION: &str = "drawproof/v1";

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChainRef {
    pub network: String,
    pub hash: String,
    pub public_key: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BeaconRef {
    pub round: u64,
    pub signature: String,
    pub randomness: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SampleItem {
    pub index: u64,
    pub item_id: String,
    pub item_hash: String,
    pub proof: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Bundle {
    pub version: String,
    pub chain: ChainRef,
    pub commitment: Commitment,
    pub beacon: BeaconRef,
    pub required: u64,
    pub receipts: Vec<receipt::Receipt>,
    pub sample: Vec<SampleItem>,
}

#[derive(Clone, Debug)]
pub struct VerifiedReceipt {
    pub receipt: receipt::Receipt,
    pub counted: bool,
    pub timely: bool,
}

#[derive(Clone, Debug)]
pub struct VerifiedBundle {
    pub chain: String,
    pub commitment: Commitment,
    pub commitment_sha256: String,
    pub beacon_round: u64,
    pub randomness: String,
    pub required: u64,
    pub receipts_present: u64,
    pub timely_receipts: u64,
    pub sample_count: u64,
    pub sample: Vec<SampleItem>,
    pub receipts: Vec<VerifiedReceipt>,
    pub policy_applied: bool,
    pub policy_signers: u64,
}

pub fn build(
    manifest: &Manifest,
    commitment: &Commitment,
    beacon_proof: &VerifiedBeacon,
    receipts: Vec<receipt::Receipt>,
    required: u64,
) -> Result<Bundle> {
    commitment.validate()?;
    let root = util::canonical::<32>(&commitment.root, "commitment.root")?;
    if root != manifest.root {
        return Err(field("commitment.root", "does not match the manifest"));
    }
    if commitment.n != manifest.len() {
        return Err(field("commitment.n", "does not match the manifest"));
    }
    let selection_round = commitment
        .round
        .checked_add(2)
        .ok_or_else(|| field("commitment.round", "round overflow"))?;
    if beacon_proof.round() != selection_round {
        return Err(field(
            "beacon.round",
            format!(
                "expected round {selection_round}, got {}",
                beacon_proof.round()
            ),
        ));
    }
    if required == 0 {
        return Err(field("bundle.required", "must be positive"));
    }
    if required > receipts.len() as u64 {
        return Err(field(
            "bundle.required",
            format!("need {required} receipts, have {}", receipts.len()),
        ));
    }
    let mut keys = HashSet::new();
    let mut timely = 0u64;
    for item in &receipts {
        receipt::verify(commitment, item)?;
        let public_key = util::canonical::<32>(&item.public_key, "receipt.public_key")?;
        if !keys.insert(public_key) {
            return Err(field("receipt.public_key", "duplicate server key"));
        }
        if item.signed_at_round < beacon_proof.round() {
            timely += 1;
        }
    }
    if timely < required {
        return Err(field(
            "bundle.required",
            format!("{timely} timely receipts, need {required}"),
        ));
    }
    let indices = derive::indices(beacon_proof.randomness(), &root, commitment.n, commitment.k)?;
    let sample = indices
        .iter()
        .map(|&index| {
            let entry = &manifest.entries[index as usize];
            let proof = manifest.proof(index as usize);
            SampleItem {
                index,
                item_id: entry.id.clone(),
                item_hash: entry.sha256.clone(),
                proof: proof.iter().map(hex::encode).collect(),
            }
        })
        .collect();
    let chain = beacon::chain();
    Ok(Bundle {
        version: VERSION.to_string(),
        chain: ChainRef {
            network: chain.beacon_id().to_string(),
            hash: chain.hash().to_string(),
            public_key: hex::encode(chain.public_key()),
        },
        commitment: commitment.clone(),
        beacon: BeaconRef {
            round: beacon_proof.round(),
            signature: hex::encode(&beacon_proof.beacon().signature),
            randomness: hex::encode(beacon_proof.randomness()),
        },
        required,
        receipts,
        sample,
    })
}

pub fn verify(bundle: &Bundle) -> Result<VerifiedBundle> {
    verify_with_policy(bundle, &[], None)
}

pub fn verify_with_policy(
    bundle: &Bundle,
    signers: &[[u8; 32]],
    required: Option<u64>,
) -> Result<VerifiedBundle> {
    if bundle.version != VERSION {
        return Err(field(
            "bundle.version",
            format!("unsupported version {:?}", bundle.version),
        ));
    }
    let chain = beacon::chain();
    if bundle.chain.network != chain.beacon_id() {
        return Err(field(
            "bundle.chain.network",
            format!("expected {:?}", chain.beacon_id()),
        ));
    }
    if bundle.chain.hash != chain.hash().to_string() {
        return Err(field(
            "bundle.chain.hash",
            format!("expected {:?}", chain.hash().to_string()),
        ));
    }
    if bundle.chain.public_key != hex::encode(chain.public_key()) {
        return Err(field("bundle.chain.public_key", "does not match quicknet"));
    }
    bundle.commitment.validate()?;
    let root = util::canonical::<32>(&bundle.commitment.root, "commitment.root")?;
    let selection_round = bundle
        .commitment
        .round
        .checked_add(2)
        .ok_or_else(|| field("commitment.round", "round overflow"))?;
    if bundle.beacon.round != selection_round {
        return Err(field(
            "beacon.round",
            format!(
                "expected round {selection_round}, got {}",
                bundle.beacon.round
            ),
        ));
    }
    let signature = util::canonical::<48>(&bundle.beacon.signature, "beacon.signature")?;
    let randomness = util::canonical::<32>(&bundle.beacon.randomness, "beacon.randomness")?;
    let beacon = Beacon::from_hex(bundle.beacon.round, &hex::encode(signature), None)
        .map_err(|error| field("beacon.signature", error.to_string()))?;
    let verified = beacon::verify(&beacon)?;
    if verified.chain_hash() != chain.hash() {
        return Err(field("beacon.chain", "does not match quicknet"));
    }
    if verified.randomness() != &randomness {
        return Err(field(
            "beacon.randomness",
            "does not match sha256(signature)",
        ));
    }
    if bundle.sample.len() as u64 != bundle.commitment.k {
        return Err(field(
            "sample.length",
            format!(
                "expected {} items, got {}",
                bundle.commitment.k,
                bundle.sample.len()
            ),
        ));
    }
    let indices = derive::indices(
        verified.randomness(),
        &root,
        bundle.commitment.n,
        bundle.commitment.k,
    )?;
    let mut sample_ids = HashSet::new();
    for (position, item) in bundle.sample.iter().enumerate() {
        if !sample_ids.insert(item.item_id.as_str()) {
            return Err(field(
                "sample.item_id",
                format!("sample[{position}] repeats an earlier item id"),
            ));
        }
        if item.index != indices[position] {
            return Err(field(
                "sample.index",
                format!(
                    "sample[{position}] expected {}, got {}",
                    indices[position], item.index
                ),
            ));
        }
        util::validate_id(&item.item_id, "sample.item_id")?;
        let item_hash = util::canonical::<32>(&item.item_hash, "sample.item_hash")?;
        let leaf = leaf_hash(&item.item_id, &item_hash);
        let mut proof = Vec::with_capacity(item.proof.len());
        for value in &item.proof {
            proof.push(util::canonical::<32>(value, "sample.proof")?);
        }
        if !merkle::verify_inclusion(leaf, item.index, bundle.commitment.n, &proof, root) {
            return Err(field(
                "sample.proof",
                format!("sample[{position}] does not lead to commitment.root"),
            ));
        }
    }
    if bundle.required == 0 {
        return Err(field("bundle.required", "must be positive"));
    }
    let policy_applied = !signers.is_empty();
    let mut allowlist = HashSet::new();
    for key in signers {
        if !allowlist.insert(*key) {
            return Err(field("policy.signer", "contains a duplicate key"));
        }
    }
    let required_count = if policy_applied {
        let count = required.unwrap_or(signers.len() as u64);
        if count == 0 || count > signers.len() as u64 {
            return Err(field(
                "policy.required",
                format!("need {count} of {} allowlisted signers", signers.len()),
            ));
        }
        count
    } else {
        if required.is_some() {
            return Err(field(
                "policy.required",
                "requires at least one allowlisted signer",
            ));
        }
        bundle.required
    };
    let threshold_field = if policy_applied {
        "policy.required"
    } else {
        "bundle.required"
    };
    if (bundle.receipts.len() as u64) < required_count {
        return Err(field(
            threshold_field,
            format!(
                "need {required_count} receipts, have {}",
                bundle.receipts.len()
            ),
        ));
    }
    let mut keys = HashSet::new();
    let mut timely = 0u64;
    let mut verified_receipts = Vec::with_capacity(bundle.receipts.len());
    for item in &bundle.receipts {
        receipt::verify(&bundle.commitment, item)?;
        let public_key = util::canonical::<32>(&item.public_key, "receipt.public_key")?;
        if !keys.insert(public_key) {
            return Err(field("receipt.public_key", "duplicate server key"));
        }
        let counted = !policy_applied || allowlist.contains(&public_key);
        let is_timely = counted && item.signed_at_round < bundle.beacon.round;
        if is_timely {
            timely += 1;
        }
        verified_receipts.push(VerifiedReceipt {
            receipt: item.clone(),
            counted,
            timely: is_timely,
        });
    }
    if timely < required_count {
        return Err(field(
            threshold_field,
            format!(
                "{timely} timely {}receipts, need {required_count}",
                if policy_applied { "allowlisted " } else { "" }
            ),
        ));
    }
    let commitment_sha256 = hex::encode(bundle.commitment.sha256()?);
    Ok(VerifiedBundle {
        chain: chain.beacon_id().to_string(),
        commitment: bundle.commitment.clone(),
        commitment_sha256,
        beacon_round: bundle.beacon.round,
        randomness: bundle.beacon.randomness.clone(),
        required: required_count,
        receipts_present: bundle.receipts.len() as u64,
        timely_receipts: timely,
        sample_count: bundle.commitment.k,
        sample: bundle.sample.clone(),
        receipts: verified_receipts,
        policy_applied,
        policy_signers: signers.len() as u64,
    })
}

impl Bundle {
    pub fn load(path: &Path) -> Result<Self> {
        let bytes = files::read_capped(path, files::MAX_BUNDLE_BYTES, "bundle")?;
        serde_json::from_slice(&bytes)
            .map_err(|error| field("bundle", format!("invalid JSON: {error}")))
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        let bytes = serde_json::to_vec_pretty(self)?;
        std::fs::write(path, bytes)
            .map_err(|error| field("bundle", format!("{}: {error}", path.display())))
    }
}

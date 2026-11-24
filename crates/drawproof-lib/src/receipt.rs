use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};

use crate::commitment::Commitment;
use crate::error::{Result, field};
use crate::util;

const RECEIPT_DOMAIN: &str = "drawproof/v1/receipt";

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Receipt {
    pub server: String,
    pub public_key: String,
    pub signature: String,
    pub signed_at_round: u64,
    pub commitment_sha256: String,
}

pub fn message(commitment: &Commitment, server: &str, signed_at_round: u64) -> Result<Vec<u8>> {
    util::validate_name(server, "receipt.server")?;
    if signed_at_round == 0 {
        return Err(field("receipt.signed_at_round", "must be positive"));
    }
    let canonical = commitment.canonical_bytes()?;
    let mut out = Vec::with_capacity(RECEIPT_DOMAIN.len() + server.len() + canonical.len() + 40);
    out.extend_from_slice(RECEIPT_DOMAIN.as_bytes());
    out.extend_from_slice(b"\nserver=");
    out.extend_from_slice(server.as_bytes());
    out.extend_from_slice(b"\nsigned_at_round=");
    out.extend_from_slice(signed_at_round.to_string().as_bytes());
    out.push(b'\n');
    out.extend_from_slice(&canonical);
    Ok(out)
}

pub fn sign(
    commitment: &Commitment,
    key: &SigningKey,
    server: &str,
    signed_at_round: u64,
) -> Result<Receipt> {
    let payload = message(commitment, server, signed_at_round)?;
    let signature = key.sign(&payload);
    Ok(Receipt {
        server: server.to_string(),
        public_key: hex::encode(key.verifying_key().to_bytes()),
        signature: hex::encode(signature.to_bytes()),
        signed_at_round,
        commitment_sha256: hex::encode(commitment.sha256()?),
    })
}

pub fn verify(commitment: &Commitment, receipt: &Receipt) -> Result<()> {
    util::validate_name(&receipt.server, "receipt.server")?;
    if receipt.signed_at_round == 0 {
        return Err(field("receipt.signed_at_round", "must be positive"));
    }
    let public_key = util::canonical::<32>(&receipt.public_key, "receipt.public_key")?;
    let key = VerifyingKey::from_bytes(&public_key)
        .map_err(|error| field("receipt.public_key", error.to_string()))?;
    let signature_bytes = util::canonical::<64>(&receipt.signature, "receipt.signature")?;
    let signature = Signature::from_bytes(&signature_bytes);
    let expected = commitment.sha256()?;
    let claimed = util::canonical::<32>(&receipt.commitment_sha256, "receipt.commitment_sha256")?;
    if claimed != expected {
        return Err(field(
            "receipt.commitment_sha256",
            "does not match the commitment",
        ));
    }
    let payload = message(commitment, &receipt.server, receipt.signed_at_round)?;
    key.verify_strict(&payload, &signature)
        .map_err(|error| field("receipt.signature", error.to_string()))
}

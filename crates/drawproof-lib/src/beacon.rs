use std::io::Read;
use std::time::{Duration, Instant};

use drand::{Beacon, ChainInfo, UnixTime, VerifiedBeacon, Verifier, chains};
use serde::Deserialize;

use crate::error::{Error, Result, field};

pub const DEFAULT_URL: &str = "https://api.drand.sh";
const MAX_LATEST_ROUND_LAG: u64 = 4;

#[derive(Deserialize)]
struct RelayBeacon {
    round: u64,
    signature: String,
}

pub fn chain() -> ChainInfo {
    chains::quicknet()
}

pub fn parse(bytes: &[u8]) -> Result<Beacon> {
    let relay: RelayBeacon = serde_json::from_slice(bytes)
        .map_err(|error| field("beacon", format!("invalid JSON: {error}")))?;
    Beacon::from_hex(relay.round, &relay.signature, None)
        .map_err(|error| field("beacon.signature", error.to_string()))
}

pub fn verify(beacon: &Beacon) -> Result<VerifiedBeacon> {
    let verifier = Verifier::new(&chain()).map_err(|error| field("beacon", error.to_string()))?;
    verifier
        .verify(beacon)
        .map_err(|error| field("beacon.signature", error.to_string()))
}

pub fn verify_json(bytes: &[u8], expected_round: u64) -> Result<VerifiedBeacon> {
    let beacon = parse(bytes)?;
    if beacon.round != expected_round {
        return Err(field(
            "beacon.round",
            format!("expected {expected_round}, got {}", beacon.round),
        ));
    }
    verify(&beacon)
}

pub fn fetch_round(
    base_url: &str,
    round: u64,
    timeout: Duration,
) -> Result<Option<VerifiedBeacon>> {
    if round == 0 {
        return Err(field("beacon.round", "must be positive"));
    }
    let url = format!(
        "{}/{}/public/{round}",
        base_url.trim_end_matches('/'),
        chain().hash()
    );
    match get(&url, timeout) {
        Ok(bytes) => Ok(Some(verify_json(&bytes, round)?)),
        Err(FetchError::NotFound) => Ok(None),
        Err(FetchError::Other(error)) => Err(field("beacon.fetch", error)),
    }
}

pub fn fetch_latest(base_url: &str, timeout: Duration) -> Result<VerifiedBeacon> {
    let url = format!(
        "{}/{}/public/latest",
        base_url.trim_end_matches('/'),
        chain().hash()
    );
    let bytes = get(&url, timeout).map_err(|error| match error {
        FetchError::NotFound => field("beacon.fetch", "latest beacon not found"),
        FetchError::Other(error) => field("beacon.fetch", error),
    })?;
    let verified = verify(&parse(&bytes)?)?;
    if base_url.trim_end_matches('/') == DEFAULT_URL {
        ensure_fresh(&verified)?;
    }
    Ok(verified)
}

fn ensure_fresh(beacon: &VerifiedBeacon) -> Result<()> {
    let now = UnixTime::from(std::time::SystemTime::now());
    let Some(expected) = chain().schedule().round_at(now) else {
        return Ok(());
    };
    if beacon.round().saturating_add(MAX_LATEST_ROUND_LAG) < expected {
        return Err(field(
            "beacon.freshness",
            format!(
                "round {} is more than {MAX_LATEST_ROUND_LAG} rounds behind the local clock ({expected})",
                beacon.round()
            ),
        ));
    }
    Ok(())
}

pub fn wait_for_round(base_url: &str, round: u64, timeout: Duration) -> Result<VerifiedBeacon> {
    let deadline = Instant::now()
        .checked_add(timeout)
        .ok_or_else(|| field("beacon.timeout", "is too large"))?;
    let mut last_error = None;
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(last_error.take().unwrap_or_else(|| {
                field(
                    "beacon.round",
                    format!("round {round} was not available before the timeout"),
                )
            }));
        }
        let attempt = remaining.min(Duration::from_secs(10));
        match fetch_round(base_url, round, attempt) {
            Ok(Some(beacon)) => return Ok(beacon),
            Ok(None) => {}
            Err(Error::Field(message)) if message.starts_with("beacon.fetch") => {
                last_error = Some(Error::Field(message));
            }
            Err(error) => return Err(error),
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(last_error.take().unwrap_or_else(|| {
                field(
                    "beacon.round",
                    format!("round {round} was not available before the timeout"),
                )
            }));
        }
        std::thread::sleep(remaining.min(Duration::from_millis(500)));
    }
}

enum FetchError {
    NotFound,
    Other(String),
}

const MAX_BEACON_BYTES: u64 = 64 * 1024;

fn get(url: &str, timeout: Duration) -> std::result::Result<Vec<u8>, FetchError> {
    let agent = ureq::AgentBuilder::new().timeout(timeout).build();
    match agent.get(url).call() {
        Ok(response) => {
            let mut body = Vec::new();
            response
                .into_reader()
                .take(MAX_BEACON_BYTES + 1)
                .read_to_end(&mut body)
                .map_err(|error| FetchError::Other(format!("read {url}: {error}")))?;
            if body.len() as u64 > MAX_BEACON_BYTES {
                return Err(FetchError::Other(format!(
                    "{url}: response exceeds {MAX_BEACON_BYTES} bytes"
                )));
            }
            Ok(body)
        }
        Err(ureq::Error::Status(code, _)) if code == 404 || code == 425 => {
            Err(FetchError::NotFound)
        }
        Err(error) => Err(FetchError::Other(format!("{url}: {error}"))),
    }
}

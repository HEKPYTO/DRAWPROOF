use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Result, bail};
use clap::{Args, Parser, Subcommand};
use drawproof_lib::commitment::Commitment;
use drawproof_lib::files::{MAX_DOCUMENT_BYTES, read_capped};
use drawproof_lib::manifest::Manifest;
use drawproof_lib::{beacon, bundle, keyfile, receipt, report};

#[derive(Parser)]
#[command(
    name = "drawproof",
    version,
    about = "Commit, draw, and verify a public-randomness sample"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    Keygen(Keygen),
    Commit(Commit),
    Draw(Draw),
    Verify(Verify),
    Report(Report),
}

#[derive(Args)]
struct Keygen {
    #[arg(long)]
    name: String,
    #[arg(long)]
    out: PathBuf,
}

#[derive(Args)]
struct Commit {
    #[arg(long)]
    manifest: PathBuf,
    #[arg(long)]
    k: u64,
    #[arg(long, default_value_t = 0)]
    lead_rounds: u64,
    #[arg(long, default_value = beacon::DEFAULT_URL)]
    beacon_url: String,
    #[arg(long, default_value_t = 120)]
    timeout: u64,
    #[arg(long)]
    out: PathBuf,
}

#[derive(Args)]
struct Draw {
    #[arg(long)]
    manifest: PathBuf,
    #[arg(long)]
    k: u64,
    #[arg(long)]
    signer_key: Option<PathBuf>,
    #[arg(long = "receipt")]
    receipts: Vec<PathBuf>,
    #[arg(long)]
    commitment: Option<PathBuf>,
    #[arg(long, default_value_t = 1)]
    required: u64,
    #[arg(long, default_value = beacon::DEFAULT_URL)]
    beacon_url: String,
    #[arg(long, default_value_t = 120)]
    timeout: u64,
    #[arg(long, default_value = "bundle.json")]
    out: PathBuf,
}

#[derive(Args)]
struct Verify {
    bundle: PathBuf,
    #[arg(long = "signer")]
    signers: Vec<String>,
    #[arg(long)]
    required: Option<u64>,
    #[arg(long)]
    allow_unpinned: bool,
}

#[derive(Args)]
struct Report {
    bundle: PathBuf,
    #[arg(long, default_value = "report.html")]
    out: PathBuf,
    #[arg(long = "signer")]
    signers: Vec<String>,
    #[arg(long)]
    required: Option<u64>,
    #[arg(long)]
    allow_unpinned: bool,
}

fn main() {
    match run() {
        Ok(code) => std::process::exit(code as i32),
        Err(error) => {
            eprintln!("error: {error:#}");
            std::process::exit(1);
        }
    }
}

fn run() -> Result<u8> {
    match Cli::parse().command {
        Command::Keygen(args) => {
            keygen(args)?;
            Ok(0)
        }
        Command::Commit(args) => {
            commit(args)?;
            Ok(0)
        }
        Command::Draw(args) => {
            draw(args)?;
            Ok(0)
        }
        Command::Verify(args) => verify(args),
        Command::Report(args) => report(args),
    }
}

fn parse_signers(values: &[String]) -> Result<Vec<[u8; 32]>> {
    values
        .iter()
        .map(|value| {
            let bytes =
                hex::decode(value).map_err(|_| anyhow::anyhow!("policy.signer: invalid hex"))?;
            bytes
                .try_into()
                .map_err(|_| anyhow::anyhow!("policy.signer: expected 32 bytes"))
        })
        .collect()
}

fn verify_bundle(
    path: &std::path::Path,
    signers: &[String],
    required: Option<u64>,
) -> Result<bundle::VerifiedBundle> {
    let signers = parse_signers(signers)?;
    if required.is_some() && signers.is_empty() {
        bail!("policy.required: --required needs at least one --signer");
    }
    let bundle = bundle::Bundle::load(path)?;
    Ok(bundle::verify_with_policy(&bundle, &signers, required)?)
}

fn keygen(args: Keygen) -> Result<()> {
    let key = keyfile::generate(&args.name)?;
    keyfile::write(&args.out, &key)?;
    let public_key = hex::encode(key.signing_key()?.verifying_key().to_bytes());
    println!("key: {}", args.out.display());
    println!("server: {}", args.name);
    println!("public key: {public_key}");
    Ok(())
}

fn commit(args: Commit) -> Result<()> {
    let manifest = Manifest::load(&args.manifest)?;
    let timeout = Duration::from_secs(args.timeout);
    let latest = beacon::fetch_latest(&args.beacon_url, timeout)?;
    let round = latest
        .round()
        .checked_add(args.lead_rounds)
        .ok_or_else(|| anyhow::anyhow!("commitment.round: overflow"))?;
    let commitment = Commitment::new(
        manifest.root,
        manifest.len(),
        args.k,
        round,
        Commitment::random_nonce()?,
    );
    commitment.validate()?;
    std::fs::write(&args.out, serde_json::to_vec_pretty(&commitment)?)?;
    println!("commitment: {}", args.out.display());
    println!("registration round: {}", commitment.round);
    println!(
        "selection round: {}",
        commitment
            .round
            .checked_add(2)
            .ok_or_else(|| anyhow::anyhow!("commitment.round: overflow"))?
    );
    Ok(())
}

fn draw(args: Draw) -> Result<()> {
    if args.signer_key.is_none() && args.receipts.is_empty() {
        bail!("provide --signer-key or at least one --receipt");
    }
    let manifest = Manifest::load(&args.manifest)?;
    let timeout = Duration::from_secs(args.timeout);
    let commitment = match &args.commitment {
        Some(path) => {
            let bytes = read_capped(path, MAX_DOCUMENT_BYTES, "commitment")?;
            serde_json::from_slice::<Commitment>(&bytes)?
        }
        None => {
            let latest = beacon::fetch_latest(&args.beacon_url, timeout)?;
            Commitment::new(
                manifest.root,
                manifest.len(),
                args.k,
                latest.round(),
                Commitment::random_nonce()?,
            )
        }
    };
    commitment.validate()?;
    if commitment.root != manifest.root_hex() {
        bail!("commitment.root: does not match the manifest");
    }
    if commitment.n != manifest.len() {
        bail!("commitment.n: does not match the manifest");
    }
    if commitment.k != args.k {
        bail!("commitment.k: does not match --k");
    }
    let mut receipts = Vec::new();
    for path in &args.receipts {
        let bytes = read_capped(path, MAX_DOCUMENT_BYTES, "receipt")?;
        receipts.push(serde_json::from_slice::<receipt::Receipt>(&bytes)?);
    }
    let available = receipts.len() as u64 + u64::from(args.signer_key.is_some());
    if args.required == 0 || args.required > available {
        bail!(
            "bundle.required: need {} receipts, have {available}",
            args.required
        );
    }
    if let Some(path) = &args.signer_key {
        let (name, key) = keyfile::load(path)?;
        let latest = beacon::fetch_latest(&args.beacon_url, timeout)?;
        let selection = commitment
            .round
            .checked_add(2)
            .ok_or_else(|| anyhow::anyhow!("commitment.round: overflow"))?;
        if latest.round() >= selection {
            bail!(
                "receipt.signed_at_round: selection round {selection} already emitted; refuse to sign late"
            );
        }
        receipts.push(receipt::sign(&commitment, &key, &name, latest.round())?);
    }
    let selection = commitment
        .round
        .checked_add(2)
        .ok_or_else(|| anyhow::anyhow!("commitment.round: overflow"))?;
    let beacon = beacon::wait_for_round(&args.beacon_url, selection, timeout)?;
    let built = bundle::build(&manifest, &commitment, &beacon, receipts, args.required)?;
    let verified = bundle::verify(&built)?;
    built.save(&args.out)?;
    println!("bundle: {}", args.out.display());
    println!("root: {}", verified.commitment.root);
    println!("beacon round: {}", verified.beacon_round);
    println!("sample: {}", verified.sample_count);
    println!(
        "receipts: {} timely, {} present, {} required",
        verified.timely_receipts, verified.receipts_present, verified.required
    );
    Ok(())
}

fn verify(args: Verify) -> Result<u8> {
    let verified = verify_bundle(&args.bundle, &args.signers, args.required)?;
    if verified.policy_applied {
        println!("bundle is valid under the supplied signer policy");
    } else {
        println!("bundle is internally consistent; no signer policy supplied");
    }
    println!("chain: {}", verified.chain);
    println!("commitment: {}", verified.commitment_sha256);
    println!(
        "dataset: {} items, sample: {}",
        verified.commitment.n, verified.sample_count
    );
    println!("beacon round: {}", verified.beacon_round);
    println!(
        "receipts: {} timely, {} present, {} required",
        verified.timely_receipts, verified.receipts_present, verified.required
    );
    if verified.policy_applied {
        println!(
            "signer policy: {} of {} allowlisted signers",
            verified.required, verified.policy_signers
        );
        return Ok(0);
    }
    println!("signer policy: not supplied");
    if args.allow_unpinned {
        println!("warning: local-only check; not independent evidence");
        return Ok(0);
    }
    eprintln!(
        "error: policy.required: no signer policy supplied; pass --signer HEX or --allow-unpinned for a local-only check"
    );
    Ok(3)
}

fn report(args: Report) -> Result<u8> {
    let verified = verify_bundle(&args.bundle, &args.signers, args.required)?;
    if !verified.policy_applied && !args.allow_unpinned {
        eprintln!(
            "error: policy.required: no signer policy supplied; pass --signer HEX or --allow-unpinned for a local-only report"
        );
        return Ok(3);
    }
    std::fs::write(&args.out, report::html(&verified))?;
    if verified.policy_applied {
        println!("report: {}", args.out.display());
    } else {
        println!(
            "report: {} (local-only; no signer policy supplied)",
            args.out.display()
        );
    }
    Ok(0)
}

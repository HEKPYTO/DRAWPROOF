use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use drawproof_lib::commitment::Commitment;
use drawproof_lib::files::{MAX_DOCUMENT_BYTES, read_capped};
use drawproof_lib::{beacon, keyfile, receipt};

#[derive(Parser)]
#[command(
    name = "drawproof-server",
    version,
    about = "Sign DRAWPROOF commitments before the selection round"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    Sign(Sign),
}

#[derive(clap::Args)]
struct Sign {
    #[arg(long)]
    key: PathBuf,
    #[arg(long)]
    commitment: PathBuf,
    #[arg(long, default_value = beacon::DEFAULT_URL)]
    beacon_url: String,
    #[arg(long, default_value_t = 120)]
    timeout: u64,
    #[arg(long)]
    out: PathBuf,
}

fn main() {
    if let Err(error) = run() {
        eprintln!("error: {error:#}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    match Cli::parse().command {
        Command::Sign(args) => sign(args),
    }
}

fn sign(args: Sign) -> Result<()> {
    let (name, key) = keyfile::load(&args.key)?;
    let bytes = read_capped(&args.commitment, MAX_DOCUMENT_BYTES, "commitment")?;
    let commitment: Commitment =
        serde_json::from_slice(&bytes).context("commitment: invalid JSON")?;
    commitment.validate()?;
    let timeout = Duration::from_secs(args.timeout);
    let latest = beacon::fetch_latest(&args.beacon_url, timeout)?;
    let selection = commitment
        .round
        .checked_add(2)
        .ok_or_else(|| anyhow::anyhow!("commitment.round: overflow"))?;
    if latest.round() >= selection {
        bail!(
            "commitment.round: selection round {selection} already emitted (latest {}); refuse to sign late",
            latest.round()
        );
    }
    if beacon::fetch_round(&args.beacon_url, selection, timeout)?.is_some() {
        bail!(
            "commitment.round: selection round {selection} is already available; refuse to sign late"
        );
    }
    let receipt = receipt::sign(&commitment, &key, &name, latest.round())?;
    std::fs::write(&args.out, serde_json::to_vec_pretty(&receipt)?)?;
    println!("receipt: {}", args.out.display());
    println!("server: {name}");
    println!("signed at round: {}", latest.round());
    println!("selection round: {selection}");
    Ok(())
}

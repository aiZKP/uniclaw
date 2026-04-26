//! `uniclaw-verify` — the standalone receipt verifier.
//!
//! One job: take a receipt (JSON), verify its Ed25519 signature against the
//! embedded issuer public key, and report pass/fail.
//!
//! No dependency on the Uniclaw kernel. Distributable on its own so anyone
//! can verify a receipt cold.

use anyhow::{Context, Result, bail};
use clap::Parser;
use ed25519_dalek::{Verifier, VerifyingKey};
use uniclaw_receipt::Receipt;

/// Verify a Uniclaw receipt.
#[derive(Debug, Parser)]
#[command(version, about, long_about = None)]
struct Cli {
    /// Path to a JSON-encoded receipt. Use `-` for stdin.
    receipt: String,

    /// Print the verified body as pretty JSON on success.
    #[arg(long)]
    print: bool,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    let bytes = read_input(&cli.receipt).context("read receipt input")?;
    let receipt: Receipt = serde_json::from_slice(&bytes).context("parse receipt JSON")?;

    verify(&receipt).context("verify receipt")?;

    println!("ok: receipt {} verified", hex(&receipt.content_id().0));

    if cli.print {
        let pretty = serde_json::to_string_pretty(&receipt.body)?;
        println!("{pretty}");
    }

    Ok(())
}

fn read_input(path: &str) -> Result<Vec<u8>> {
    use std::io::Read;
    if path == "-" {
        let mut buf = Vec::new();
        std::io::stdin().read_to_end(&mut buf)?;
        Ok(buf)
    } else {
        std::fs::read(path).map_err(Into::into)
    }
}

/// Verify the Ed25519 signature on the receipt body.
fn verify(receipt: &Receipt) -> Result<()> {
    let body_bytes = serde_json::to_vec(&receipt.body)?;

    let key = VerifyingKey::from_bytes(&receipt.issuer.0).context("invalid issuer public key")?;

    let signature = ed25519_dalek::Signature::from_bytes(&receipt.signature.0);

    key.verify(&body_bytes, &signature)
        .map_err(|e| anyhow::anyhow!("signature verification failed: {e}"))?;

    if receipt.version != uniclaw_receipt::RECEIPT_FORMAT_VERSION {
        bail!(
            "unsupported receipt version {} (this verifier supports {})",
            receipt.version,
            uniclaw_receipt::RECEIPT_FORMAT_VERSION
        );
    }

    Ok(())
}

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        s.push(nib(b >> 4));
        s.push(nib(b & 0xf));
    }
    s
}

fn nib(n: u8) -> char {
    match n {
        0..=9 => (b'0' + n) as char,
        10..=15 => (b'a' + n - 10) as char,
        _ => unreachable!(),
    }
}

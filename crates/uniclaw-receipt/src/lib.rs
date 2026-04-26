//! Receipt format types for the Uniclaw verifiable agent runtime.
//!
//! A receipt is a signed, verifiable record that an agent action occurred.
//! Receipts are addressable by their content hash: `uniclaw://receipt/<hash>`.
//!
//! This crate is intentionally small. Signing and verification logic lives in
//! `uniclaw-verify` so that the verifier remains a tiny standalone binary that
//! anyone can install without pulling in the kernel.
//!
//! Receipt format spec: see `RFCS/0001-receipt-format.md`.

#![cfg_attr(not(test), no_std)]

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;

use serde::{Deserialize, Serialize};

/// Wire-format version. Bumped on any breaking schema change.
pub const RECEIPT_FORMAT_VERSION: u32 = 1;

/// A 32-byte BLAKE3 digest, used for content addressing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Digest(#[serde(with = "hex_array")] pub [u8; 32]);

/// A 64-byte Ed25519 signature.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Signature(#[serde(with = "hex_array_64")] pub [u8; 64]);

/// A 32-byte Ed25519 public key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicKey(#[serde(with = "hex_array")] pub [u8; 32]);

/// A signed receipt. The kernel's primary verifiable output.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Receipt {
    /// Wire-format version.
    pub version: u32,
    /// Body of the receipt — what the signature covers.
    pub body: ReceiptBody,
    /// Issuer's Ed25519 public key.
    pub issuer: PublicKey,
    /// Ed25519 signature over the canonical encoding of `body`.
    pub signature: Signature,
}

/// The signed portion of a receipt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReceiptBody {
    /// Receipt schema version.
    pub schema_version: u32,
    /// RFC 3339 timestamp.
    pub issued_at: String,
    /// Action that produced this receipt.
    pub action: Action,
    /// Decision the kernel made.
    pub decision: Decision,
    /// Constitution rule IDs that fired (if any).
    pub constitution_rules: Vec<RuleRef>,
    /// Provenance edges recorded for this action.
    pub provenance: Vec<ProvenanceEdge>,
    /// Hash of the redactor stack that ran on the output (if any).
    pub redactor_stack_hash: Option<Digest>,
    /// Position of this action in the Merkle audit chain.
    pub merkle_leaf: MerkleLeaf,
}

/// What the agent attempted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Action {
    pub kind: String,
    pub target: String,
    pub input_hash: Digest,
}

/// The kernel's decision on the action.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Decision {
    Allowed,
    Denied,
    Approved,
    Pending,
}

/// Reference to a Constitution rule by id.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuleRef {
    pub id: String,
    pub matched: bool,
}

/// Typed edge in the provenance graph.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProvenanceEdge {
    pub from: String,
    pub to: String,
    pub kind: String,
}

/// Position of this action in the Merkle audit chain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MerkleLeaf {
    pub sequence: u64,
    pub leaf_hash: Digest,
    pub prev_hash: Digest,
}

impl Receipt {
    /// Compute the content-addressable id of the receipt.
    ///
    /// The id is BLAKE3 of the canonical JSON encoding of the body.
    /// (Content-addressing the body, not the wrapper, lets us add fields to
    /// the wrapper later without breaking existing receipt URLs.)
    #[must_use]
    pub fn content_id(&self) -> Digest {
        let canonical = serde_json::to_vec(&self.body).expect("canonical body must encode");
        Digest(*blake3::hash(&canonical).as_bytes())
    }
}

// --- helpers for hex-encoding fixed-size arrays in JSON ---

mod hex_array {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8; 32], s: S) -> Result<S::Ok, S::Error> {
        encode_hex::<32>(bytes).serialize(s)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 32], D::Error> {
        let s = alloc::string::String::deserialize(d)?;
        decode_hex::<32>(&s).map_err(serde::de::Error::custom)
    }

    fn encode_hex<const N: usize>(bytes: &[u8; N]) -> alloc::string::String {
        let mut out = alloc::string::String::with_capacity(N * 2);
        for &b in bytes {
            out.push(nib(b >> 4));
            out.push(nib(b & 0xf));
        }
        out
    }

    fn decode_hex<const N: usize>(s: &str) -> Result<[u8; N], &'static str> {
        if s.len() != N * 2 {
            return Err("invalid hex length");
        }
        let mut out = [0u8; N];
        let bytes = s.as_bytes();
        for i in 0..N {
            out[i] = (un(bytes[i * 2])? << 4) | un(bytes[i * 2 + 1])?;
        }
        Ok(out)
    }

    fn nib(n: u8) -> char {
        match n {
            0..=9 => (b'0' + n) as char,
            10..=15 => (b'a' + n - 10) as char,
            _ => unreachable!(),
        }
    }

    fn un(c: u8) -> Result<u8, &'static str> {
        match c {
            b'0'..=b'9' => Ok(c - b'0'),
            b'a'..=b'f' => Ok(c - b'a' + 10),
            b'A'..=b'F' => Ok(c - b'A' + 10),
            _ => Err("invalid hex character"),
        }
    }
}

mod hex_array_64 {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8; 64], s: S) -> Result<S::Ok, S::Error> {
        encode(bytes).serialize(s)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 64], D::Error> {
        let s = alloc::string::String::deserialize(d)?;
        decode(&s).map_err(serde::de::Error::custom)
    }

    fn encode(bytes: &[u8; 64]) -> alloc::string::String {
        let mut out = alloc::string::String::with_capacity(128);
        for &b in bytes {
            out.push(nib(b >> 4));
            out.push(nib(b & 0xf));
        }
        out
    }

    fn decode(s: &str) -> Result<[u8; 64], &'static str> {
        if s.len() != 128 {
            return Err("invalid hex length");
        }
        let mut out = [0u8; 64];
        let bytes = s.as_bytes();
        for i in 0..64 {
            out[i] = (un(bytes[i * 2])? << 4) | un(bytes[i * 2 + 1])?;
        }
        Ok(out)
    }

    fn nib(n: u8) -> char {
        match n {
            0..=9 => (b'0' + n) as char,
            10..=15 => (b'a' + n - 10) as char,
            _ => unreachable!(),
        }
    }

    fn un(c: u8) -> Result<u8, &'static str> {
        match c {
            b'0'..=b'9' => Ok(c - b'0'),
            b'a'..=b'f' => Ok(c - b'a' + 10),
            b'A'..=b'F' => Ok(c - b'A' + 10),
            _ => Err("invalid hex character"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    fn sample_body() -> ReceiptBody {
        ReceiptBody {
            schema_version: RECEIPT_FORMAT_VERSION,
            issued_at: "2026-04-26T00:00:00Z".into(),
            action: Action {
                kind: "http.fetch".into(),
                target: "https://example.com/".into(),
                input_hash: Digest([0u8; 32]),
            },
            decision: Decision::Allowed,
            constitution_rules: vec![],
            provenance: vec![],
            redactor_stack_hash: None,
            merkle_leaf: MerkleLeaf {
                sequence: 0,
                leaf_hash: Digest([0u8; 32]),
                prev_hash: Digest([0u8; 32]),
            },
        }
    }

    #[test]
    fn body_round_trips_through_json() {
        let body = sample_body();
        let encoded = serde_json::to_string(&body).expect("encode");
        let decoded: ReceiptBody = serde_json::from_str(&encoded).expect("decode");
        assert_eq!(body, decoded);
    }

    #[test]
    fn content_id_is_deterministic() {
        let receipt = Receipt {
            version: RECEIPT_FORMAT_VERSION,
            body: sample_body(),
            issuer: PublicKey([1u8; 32]),
            signature: Signature([2u8; 64]),
        };
        let id1 = receipt.content_id();
        let id2 = receipt.content_id();
        assert_eq!(id1, id2);
        // Different body → different id.
        let mut other = receipt.clone();
        other.body.merkle_leaf.sequence = 1;
        assert_ne!(receipt.content_id(), other.content_id());
    }

    #[test]
    fn content_id_ignores_signature_changes() {
        // Two receipts with identical bodies but different signatures
        // share the same content id, by design.
        let a = Receipt {
            version: RECEIPT_FORMAT_VERSION,
            body: sample_body(),
            issuer: PublicKey([1u8; 32]),
            signature: Signature([2u8; 64]),
        };
        let mut b = a.clone();
        b.signature = Signature([3u8; 64]);
        assert_eq!(a.content_id(), b.content_id());
    }
}

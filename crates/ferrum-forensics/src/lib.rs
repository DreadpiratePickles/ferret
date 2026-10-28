#![no_std]

//! `ferrum-forensics` — Pillar 4 (PROVE): SHA-256 Hash-Chained Evidence Sealing
//! & Bounded Store-and-Forward Out-of-Band Queue.
//!
//! When `FORENSIC_LOCKDOWN` triggers, PCAP blocks and camera/audio snapshots on the
//! XIAO ESP32-S3 Sense (and C5/WROOM) are sealed into a cryptographic hash chain
//! (`H_i = SHA256(H_{i-1} || seq || timestamp || policy || SHA256(block))`) so any
//! post-capture tampering invalidates the chain.

use ferrum_proto::NodeId;
use ferrum_secure::{sha256, Sha256};

/// Standard PCAP / evidence block size sealed per chain link in PSRAM.
pub const EVIDENCE_BLOCK_BYTES: usize = 256;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct EvidenceRecord {
    pub seq: u32,
    pub timestamp_s: u32,
    pub policy_mode: u8,
    pub block_hash: [u8; 32],
    pub chain_hash: [u8; 32],
}

pub struct HashChain {
    node_id: NodeId,
    seq: u32,
    tip_hash: [u8; 32],
}

fn genesis_hash(node_id: NodeId) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"FERRUM-FORENSIC-GENESIS-V1:");
    h.update(&[node_id as u8]);
    h.finalize()
}

impl HashChain {
    pub fn new(node_id: NodeId) -> Self {
        Self {
            node_id,
            seq: 0,
            tip_hash: genesis_hash(node_id),
        }
    }

    pub fn seal(
        &mut self,
        block: &[u8; EVIDENCE_BLOCK_BYTES],
        timestamp_s: u32,
        policy_mode: u8,
    ) -> EvidenceRecord {
        self.seq = self.seq.wrapping_add(1);
        let block_hash = sha256(block);

        let mut h = Sha256::new();
        h.update(&self.tip_hash);
        h.update(&self.seq.to_le_bytes());
        h.update(&timestamp_s.to_le_bytes());
        h.update(&[policy_mode]);
        h.update(&block_hash);
        let chain_hash = h.finalize();

        self.tip_hash = chain_hash;
        EvidenceRecord {
            seq: self.seq,
            timestamp_s,
            policy_mode,
            block_hash,
            chain_hash,
        }
    }

    pub fn tip(&self) -> &[u8; 32] {
        &self.tip_hash
    }

    pub fn node_id(&self) -> NodeId {
        self.node_id
    }
}

/// Verifies an ordered slice of `EvidenceRecord`s from the node's genesis seed.
pub fn verify_chain(node_id: NodeId, records: &[EvidenceRecord]) -> bool {
    let mut prev = genesis_hash(node_id);
    for (idx, rec) in records.iter().enumerate() {
        if rec.seq != (idx as u32 + 1) {
            return false;
        }
        let mut h = Sha256::new();
        h.update(&prev);
        h.update(&rec.seq.to_le_bytes());
        h.update(&rec.timestamp_s.to_le_bytes());
        h.update(&[rec.policy_mode]);
        h.update(&rec.block_hash);
        let expected = h.finalize();
        if expected != rec.chain_hash {
            return false;
        }
        prev = rec.chain_hash;
    }
    true
}

/// Fixed-capacity `#![no_std]` ring queue for store-and-forward over intermittent LoRa SX1262 links.
pub struct StoreForwardQueue<T: Copy, const CAP: usize> {
    buf: [Option<T>; CAP],
    head: usize,
    tail: usize,
    len: usize,
    pub dropped: u32,
}

impl<T: Copy, const CAP: usize> StoreForwardQueue<T, CAP> {
    pub const fn new() -> Self {
        Self {
            buf: [None; CAP],
            head: 0,
            tail: 0,
            len: 0,
            dropped: 0,
        }
    }

    pub fn push(&mut self, item: T) {
        if self.len == CAP {
            // Overwrite oldest entry to keep fresh telemetry while tracking drops
            self.head = (self.head + 1) % CAP;
            self.len -= 1;
            self.dropped = self.dropped.saturating_add(1);
        }
        self.buf[self.tail] = Some(item);
        self.tail = (self.tail + 1) % CAP;
        self.len += 1;
    }

    pub fn pop(&mut self) -> Option<T> {
        if self.len == 0 {
            return None;
        }
        let item = self.buf[self.head].take();
        self.head = (self.head + 1) % CAP;
        self.len -= 1;
        item
    }

    pub const fn len(&self) -> usize {
        self.len
    }

    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_chain_detects_tampering() {
        let mut chain = HashChain::new(NodeId::XiaoS3Sense);
        let b1 = [0x11u8; EVIDENCE_BLOCK_BYTES];
        let b2 = [0x22u8; EVIDENCE_BLOCK_BYTES];
        let r1 = chain.seal(&b1, 1000, 0x03);
        let r2 = chain.seal(&b2, 1005, 0x09);

        assert!(verify_chain(NodeId::XiaoS3Sense, &[r1, r2]));
        assert!(!verify_chain(NodeId::Esp32C5Scout, &[r1, r2]));

        let mut tampered = r2;
        tampered.timestamp_s += 1;
        assert!(!verify_chain(NodeId::XiaoS3Sense, &[r1, tampered]));
    }

    #[test]
    fn store_forward_queue_tracks_overflow_drops() {
        let mut q = StoreForwardQueue::<u32, 3>::new();
        q.push(10);
        q.push(20);
        q.push(30);
        q.push(40); // drops 10
        assert_eq!(q.dropped, 1);
        assert_eq!(q.pop(), Some(20));
        assert_eq!(q.pop(), Some(30));
        assert_eq!(q.pop(), Some(40));
        assert_eq!(q.pop(), None);
    }
}

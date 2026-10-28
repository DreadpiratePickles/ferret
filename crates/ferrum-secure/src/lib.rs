#![no_std]

//! `ferrum-secure` — Pillar 3 (DEFEND): `#![no_std]` SHA-256, HMAC-SHA256, Anti-Replay
//! Authenticated Command Channel, and LoRa Epoch Key Rotation.
//!
//! Protects `FerrumPolicyCmd` dispatches over ESP-NOW / LoRa from spoofed policy injection
//! and captured-frame replay attacks.

use ferrum_proto::FerrumPolicyCmd;

const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

/// Streaming `#![no_std]` SHA-256 implementation (FIPS 180-4).
#[derive(Clone)]
pub struct Sha256 {
    state: [u32; 8],
    buf: [u8; 64],
    buf_len: usize,
    total_len: u64,
}

impl Sha256 {
    pub const fn new() -> Self {
        Self {
            state: [
                0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
            ],
            buf: [0u8; 64],
            buf_len: 0,
            total_len: 0,
        }
    }

    pub fn update(&mut self, data: &[u8]) {
        self.total_len = self.total_len.wrapping_add(data.len() as u64);
        let mut i = 0;
        while i < data.len() {
            let space = 64 - self.buf_len;
            let take = (data.len() - i).min(space);
            self.buf[self.buf_len..self.buf_len + take].copy_from_slice(&data[i..i + take]);
            self.buf_len += take;
            i += take;
            if self.buf_len == 64 {
                let block = self.buf;
                self.compress(&block);
                self.buf_len = 0;
            }
        }
    }

    pub fn finalize(mut self) -> [u8; 32] {
        let bit_len = self.total_len.wrapping_mul(8);
        self.buf[self.buf_len] = 0x80;
        self.buf_len += 1;

        if self.buf_len > 56 {
            while self.buf_len < 64 {
                self.buf[self.buf_len] = 0;
                self.buf_len += 1;
            }
            let block = self.buf;
            self.compress(&block);
            self.buf_len = 0;
        }

        while self.buf_len < 56 {
            self.buf[self.buf_len] = 0;
            self.buf_len += 1;
        }
        self.buf[56..64].copy_from_slice(&bit_len.to_be_bytes());
        let block = self.buf;
        self.compress(&block);

        let mut out = [0u8; 32];
        for (i, word) in self.state.iter().enumerate() {
            out[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
        }
        out
    }

    fn compress(&mut self, block: &[u8; 64]) {
        let mut w = [0u32; 64];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([
                block[i * 4],
                block[i * 4 + 1],
                block[i * 4 + 2],
                block[i * 4 + 3],
            ]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }

        let mut a = self.state[0];
        let mut b = self.state[1];
        let mut c = self.state[2];
        let mut d = self.state[3];
        let mut e = self.state[4];
        let mut f = self.state[5];
        let mut g = self.state[6];
        let mut h = self.state[7];

        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let temp1 = h
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(maj);

            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }

        self.state[0] = self.state[0].wrapping_add(a);
        self.state[1] = self.state[1].wrapping_add(b);
        self.state[2] = self.state[2].wrapping_add(c);
        self.state[3] = self.state[3].wrapping_add(d);
        self.state[4] = self.state[4].wrapping_add(e);
        self.state[5] = self.state[5].wrapping_add(f);
        self.state[6] = self.state[6].wrapping_add(g);
        self.state[7] = self.state[7].wrapping_add(h);
    }
}

/// One-shot SHA-256 digest.
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(data);
    h.finalize()
}

/// RFC 2104 HMAC-SHA256 (`#![no_std]`).
pub fn hmac_sha256(key: &[u8], msg: &[u8]) -> [u8; 32] {
    let mut k_block = [0u8; 64];
    if key.len() > 64 {
        let hashed = sha256(key);
        k_block[..32].copy_from_slice(&hashed);
    } else {
        k_block[..key.len()].copy_from_slice(key);
    }

    let mut ipad = [0x36u8; 64];
    let mut opad = [0x5cu8; 64];
    for i in 0..64 {
        ipad[i] ^= k_block[i];
        opad[i] ^= k_block[i];
    }

    let mut inner = Sha256::new();
    inner.update(&ipad);
    inner.update(msg);
    let inner_digest = inner.finalize();

    let mut outer = Sha256::new();
    outer.update(&opad);
    outer.update(&inner_digest);
    outer.finalize()
}

/// Constant-time 16-byte tag comparison to prevent timing side-channels on ESP32.
fn ct_eq_16(a: &[u8; 16], b: &[u8; 16]) -> bool {
    let mut diff = 0u8;
    for i in 0..16 {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

/// Derives an epoch-specific swarm session key from the master root key and LoRa beacon epoch.
pub fn derive_epoch_key(master_key: &[u8; 32], epoch: u32) -> [u8; 32] {
    let mut ctx = [0u8; 16];
    ctx[0..12].copy_from_slice(b"FERRUM-EPOCH");
    ctx[12..16].copy_from_slice(&epoch.to_le_bytes());
    hmac_sha256(master_key, &ctx)
}

/// 33-byte authenticated policy command frame (`4B seq + 13B FerrumPolicyCmd + 16B HMAC-SHA256-128`).
#[repr(C)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct SealedPolicyFrame {
    pub seq: u32,
    pub payload: [u8; FerrumPolicyCmd::SIZE],
    pub tag: [u8; 16],
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum OpenError {
    BadMac,
    Replay,
    CorruptPayload,
}

/// Bidirectional authenticated command channel with strict monotonic anti-replay counter.
pub struct SecureChannel {
    key: [u8; 32],
    tx_seq: u32,
    last_rx_seq: u32,
}

impl SecureChannel {
    pub const fn new(key: [u8; 32]) -> Self {
        Self {
            key,
            tx_seq: 0,
            last_rx_seq: 0,
        }
    }

    pub fn rotate_epoch(&mut self, master_key: &[u8; 32], new_epoch: u32) {
        self.key = derive_epoch_key(master_key, new_epoch);
        self.tx_seq = 0;
        self.last_rx_seq = 0;
    }

    pub fn seal(&mut self, cmd: &FerrumPolicyCmd) -> SealedPolicyFrame {
        self.tx_seq = self.tx_seq.wrapping_add(1);
        let seq = self.tx_seq;
        let payload = cmd.to_bytes();

        let mut mac_input = [0u8; 4 + FerrumPolicyCmd::SIZE];
        mac_input[0..4].copy_from_slice(&seq.to_le_bytes());
        mac_input[4..].copy_from_slice(&payload);

        let full_mac = hmac_sha256(&self.key, &mac_input);
        let mut tag = [0u8; 16];
        tag.copy_from_slice(&full_mac[..16]);

        SealedPolicyFrame { seq, payload, tag }
    }

    pub fn open(&mut self, frame: &SealedPolicyFrame) -> Result<FerrumPolicyCmd, OpenError> {
        let mut mac_input = [0u8; 4 + FerrumPolicyCmd::SIZE];
        mac_input[0..4].copy_from_slice(&frame.seq.to_le_bytes());
        mac_input[4..].copy_from_slice(&frame.payload);

        let full_mac = hmac_sha256(&self.key, &mac_input);
        let mut expected_tag = [0u8; 16];
        expected_tag.copy_from_slice(&full_mac[..16]);

        if !ct_eq_16(&frame.tag, &expected_tag) {
            return Err(OpenError::BadMac);
        }
        if frame.seq <= self.last_rx_seq {
            return Err(OpenError::Replay);
        }
        let cmd = FerrumPolicyCmd::from_bytes(&frame.payload).ok_or(OpenError::CorruptPayload)?;
        self.last_rx_seq = frame.seq;
        Ok(cmd)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ferrum_proto::{DualNrfPolicy, NodeId, PolicyMode};

    #[test]
    fn sha256_nist_kat_abc() {
        // FIPS 180-4 KAT for "abc"
        let digest = sha256(b"abc");
        let expected: [u8; 32] = [
            0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea,
            0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
            0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
            0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad,
        ];
        assert_eq!(digest, expected);
    }

    #[test]
    fn hmac_sha256_rfc4231_case1() {
        // RFC 4231 Test Case 1: Key = 20 bytes of 0x0b, Data = "Hi There"
        let key = [0x0bu8; 20];
        let mac = hmac_sha256(&key, b"Hi There");
        let expected: [u8; 32] = [
            0xb0, 0x34, 0x4c, 0x61, 0xd8, 0xdb, 0x38, 0x53,
            0x5c, 0xa8, 0xaf, 0xce, 0xaf, 0x0b, 0xf1, 0x2b,
            0x88, 0x1d, 0xc2, 0x00, 0xc9, 0x83, 0x3d, 0xa7,
            0x26, 0xe9, 0x37, 0x6c, 0x2e, 0x32, 0xcf, 0xf7,
        ];
        assert_eq!(mac, expected);
    }

    #[test]
    fn secure_channel_seals_opens_and_rejects_replay_and_tamper() {
        let key = [0xAA; 32];
        let mut tx = SecureChannel::new(key);
        let mut rx = SecureChannel::new(key);

        let cmd = FerrumPolicyCmd {
            target_node: NodeId::Broadcast as u8,
            policy_mode: PolicyMode::ForensicLockdown as u8,
            dual_nrf_mode: DualNrfPolicy::HunterKillerEsb as u8,
            pinned_channels: [98, 6, 149, 0],
            dwell_time_ms: 500,
            cpu_freq_mhz: 240,
            s3_psram_pcap_quota_kb: 4096,
            crc8: 0,
        };

        let frame = tx.seal(&cmd);
        let opened = rx.open(&frame).expect("valid seal");
        assert_eq!(opened.policy_mode, PolicyMode::ForensicLockdown as u8);

        // Replay must be rejected
        assert_eq!(rx.open(&frame), Err(OpenError::Replay));

        // Forged tag must be rejected
        let mut frame2 = tx.seal(&cmd);
        frame2.tag[0] ^= 0x01;
        assert_eq!(rx.open(&frame2), Err(OpenError::BadMac));
    }
}

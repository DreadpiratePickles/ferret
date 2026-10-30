#![no_std]

//! `ferrum-triage` — On-device feature extraction for the `MESH_SURVIVE` LoRa path.
//!
//! Instead of flooding the jammed, low-bandwidth SX1262 link with raw telemetry, each node
//! computes a compact 12-byte `FeatureVector` (fixed-point RSSI statistics, per-second rates,
//! channel-occupancy entropy, alarm flags). The Pi 5 reconstructs the situation from features.

use ferrum_proto::compute_crc8;

/// 16-bin RSSI histogram over `[-100, -21]` dBm (5 dBm per bin). O(1), no allocator.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct RssiHistogram {
    pub bins: [u16; 16],
    pub total: u32,
}

impl Default for RssiHistogram {
    fn default() -> Self {
        Self::new()
    }
}

impl RssiHistogram {
    pub const fn new() -> Self {
        Self {
            bins: [0; 16],
            total: 0,
        }
    }

    pub fn update(&mut self, rssi_dbm: i8) {
        let clamped = rssi_dbm.clamp(-100, -22);
        let idx = ((clamped as i16 + 100) / 5) as usize; // -100..-96 -> 0 ... -25..-22 -> 15
        self.bins[idx] = self.bins[idx].saturating_add(1);
        self.total = self.total.saturating_add(1);
    }

    /// Population mean in quarter-dBm fixed point; 0 when empty.
    pub fn mean_q(&self) -> i16 {
        if self.total == 0 {
            return 0;
        }
        let mut acc: i32 = 0;
        for (i, &c) in self.bins.iter().enumerate() {
            // Bin center: -97.5 + 5*i dBm -> (-390 + 20*i) quarter-dBm
            acc += c as i32 * (-390 + 20 * i as i32);
        }
        (acc / self.total as i32) as i16
    }

    /// Population stddev in quarter-dBm fixed point.
    pub fn stdev_q(&self) -> u16 {
        if self.total == 0 {
            return 0;
        }
        let mean = self.mean_q() as i32;
        let mut var: i32 = 0;
        for (i, &c) in self.bins.iter().enumerate() {
            let center = -390 + 20 * i as i32;
            let d = center - mean;
            var += c as i32 * d * d;
        }
        libm_isqrt(var / self.total as i32) as u16
    }

    pub fn dominant_bin(&self) -> u8 {
        let mut best = 0u8;
        for i in 0..16 {
            if self.bins[i] > self.bins[best as usize] {
                best = i as u8;
            }
        }
        best
    }
}

/// Small integer sqrt (no `no_std` float dependency).
fn libm_isqrt(x: i32) -> u32 {
    if x <= 0 {
        return 0;
    }
    let mut r = 0u32;
    while (r + 1) * (r + 1) <= x as u32 {
        r += 1;
    }
    r
}

/// Per-second event counter over a sliding `WINDOW`-second history.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct RateWindow<const WINDOW: usize> {
    slots: [u16; WINDOW],
    idx: usize,
    total: u32,
}

impl<const WINDOW: usize> Default for RateWindow<WINDOW> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const WINDOW: usize> RateWindow<WINDOW> {
    pub const fn new() -> Self {
        Self {
            slots: [0; WINDOW],
            idx: 0,
            total: 0,
        }
    }

    pub fn event(&mut self) {
        self.slots[self.idx] = self.slots[self.idx].saturating_add(1);
        self.total = self.total.saturating_add(1);
    }

    /// Advance one second. Call from the 1 Hz housekeeping timer, NOT per event.
    pub fn tick(&mut self) {
        self.idx = (self.idx + 1) % WINDOW;
        self.slots[self.idx] = 0;
    }

    pub fn per_sec(&self) -> u16 {
        self.slots[self.idx]
    }

    /// Average rate across the window, quarter-events-per-second fixed point.
    pub fn avg_per_sec_q(&self) -> u16 {
        ((self.total * 4) / WINDOW as u32).min(u16::MAX as u32) as u16
    }
}

/// Shannon entropy (bits, ×64 fixed point) over 16 channel-occupancy bins. Max 256 (=4.0 bits).
pub fn channel_entropy_q(counts: &[u16; 16]) -> u16 {
    let total: u32 = counts.iter().map(|&c| c as u32).sum();
    if total == 0 {
        return 0;
    }
    let mut h = 0u32;
    for &c in counts.iter() {
        if c == 0 {
            continue;
        }
        let p_num = c as u32;
        let ratio = total / p_num;
        let lb = 31 - ratio.leading_zeros();
        h += p_num * lb * 64 / total;
    }
    h.min(u16::MAX as u32) as u16
}

/// Alarm flag bits carried in the `FeatureVector`.
pub mod flags {
    pub const DEAUTH_FLOOD: u8 = 0x01;
    pub const GHOST_BAND: u8 = 0x02;
    pub const ESB_HID: u8 = 0x04;
    pub const BLE_SPAM: u8 = 0x08;
    pub const JAM: u8 = 0x10;
}

/// 12-byte compressed uplink frame for the LoRa `MESH_SURVIVE` path.
#[repr(C)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct FeatureVector {
    pub mean_rssi_q: i16,   // quarter-dBm
    pub rssi_std_q: u16,    // quarter-dBm
    pub mgmt_rate_q: u16,   // quarter-frames/sec (802.11 mgmt)
    pub deauth_rate_q: u16, // quarter-frames/sec (deauth/disassoc)
    pub entropy_q: u16,     // channel occupancy entropy ×64
    pub alarm_flags: u8,
    pub node_id: u8,
    pub crc8: u8,
}

impl FeatureVector {
    pub const SIZE: usize = 12;

    pub fn to_bytes(&self) -> [u8; Self::SIZE] {
        let mut b = [0u8; Self::SIZE];
        b[0..2].copy_from_slice(&self.mean_rssi_q.to_le_bytes());
        b[2..4].copy_from_slice(&self.rssi_std_q.to_le_bytes());
        b[4..6].copy_from_slice(&self.mgmt_rate_q.to_le_bytes());
        b[6..8].copy_from_slice(&self.deauth_rate_q.to_le_bytes());
        b[8..10].copy_from_slice(&self.entropy_q.to_le_bytes());
        b[10] = self.alarm_flags;
        b[11] = compute_crc8(&b[0..11]);
        b
    }

    pub fn from_bytes(buf: &[u8; Self::SIZE]) -> Option<Self> {
        if buf[11] != compute_crc8(&buf[0..11]) {
            return None;
        }
        Some(Self {
            mean_rssi_q: i16::from_le_bytes([buf[0], buf[1]]),
            rssi_std_q: u16::from_le_bytes([buf[2], buf[3]]),
            mgmt_rate_q: u16::from_le_bytes([buf[4], buf[5]]),
            deauth_rate_q: u16::from_le_bytes([buf[6], buf[7]]),
            entropy_q: u16::from_le_bytes([buf[8], buf[9]]),
            alarm_flags: buf[10],
            node_id: 0,
            crc8: buf[11],
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn histogram_statistics() {
        let mut h = RssiHistogram::new();
        for _ in 0..10 {
            h.update(-40);
        }
        for _ in 0..10 {
            h.update(-60);
        }
        let mean = h.mean_q();
        assert!(
            (-210..=-180).contains(&mean),
            "mean ≈ -190 quarter-dBm (-47.5dBm), got {}",
            mean
        );
        assert!(h.stdev_q() > 0);
        assert_eq!(h.dominant_bin(), 8); // bin 8 covers [-60,-56)
    }

    #[test]
    fn rate_window_averages() {
        let mut w = RateWindow::<4>::new();
        for _ in 0..8 {
            w.event();
        }
        assert_eq!(w.per_sec(), 8);
        assert_eq!(w.avg_per_sec_q(), 8 * 4 / 4);
        w.tick();
        assert_eq!(w.per_sec(), 0);
    }

    #[test]
    fn entropy_uniform_beats_sparse() {
        let uniform = [10u16; 16];
        let sparse = [160u16, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        assert!(channel_entropy_q(&uniform) > channel_entropy_q(&sparse));
    }

    #[test]
    fn feature_vector_wire_roundtrip() {
        let fv = FeatureVector {
            mean_rssi_q: -200,
            rssi_std_q: 40,
            mgmt_rate_q: 120,
            deauth_rate_q: 0,
            entropy_q: 250,
            alarm_flags: flags::JAM,
            node_id: 3,
            crc8: 0,
        };
        let b = fv.to_bytes();
        let back = FeatureVector::from_bytes(&b).expect("crc ok");
        assert_eq!(back.mean_rssi_q, fv.mean_rssi_q);
        assert_eq!(back.alarm_flags, flags::JAM);
        let mut corrupt = b;
        corrupt[0] ^= 0xFF;
        assert!(FeatureVector::from_bytes(&corrupt).is_none());
    }
}

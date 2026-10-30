//! Seed reproducibility: the flagship scenario must hash identically on every run and platform.
use ferrum_proto::NodeId;
use ferrum_sim::SimController;

/// Fixed sample set per node: (node, channels in that node's own numbering).
const PROBES: [(NodeId, &[u8]); 3] = [
    (NodeId::WroomDualNrf, &[2, 20, 40, 62, 80, 96, 98, 110, 125]),
    (NodeId::Esp32C5Scout, &[1, 6, 36, 40, 149]),
    (NodeId::XiaoS3Sense, &[1, 6, 11]),
];

struct Fnv(u64);
impl Fnv {
    fn put(&mut self, bytes: &[u8]) {
        for b in bytes {
            self.0 = (self.0 ^ u64::from(*b)).wrapping_mul(0x0000_0100_0000_01B3);
        }
    }
}

/// FNV-1a over, per tick: probe RSSIs, every sniffed frame, sub-GHz state.
fn run_hash(seed: u64, scenario: &str, ticks: u32) -> u64 {
    let mut c = SimController::new(seed, scenario);
    let mut h = Fnv(0xcbf2_9ce4_8422_2325);
    for _ in 0..ticks {
        c.advance(100);
        for (node, chans) in PROBES {
            for &ch in chans {
                h.put(&[c.world().rssi_at(node, ch) as u8]);
            }
            h.put(&(c.world().pending_frames(node) as u32).to_le_bytes());
            while let Some(f) = c.world.next_frame(node) {
                h.put(&[f.kind as u8, f.channel, f.rssi as u8]);
                h.put(&f.src.0.to_le_bytes());
                h.put(&f.t_ms.to_le_bytes());
            }
        }
        h.put(&c.subghz_burst_mhz().unwrap_or(0).to_le_bytes());
    }
    h.0
}

/// Generated once from this implementation (`seed 42`, 300 ticks x 100 ms).
const GOLDEN_RED_TEAM_42: u64 = 0xb28c_4810_73ea_7536;

#[test]
fn test_red_team_incursion_is_reproducible() {
    let a = run_hash(42, "red-team-incursion", 300);
    let b = run_hash(42, "red-team-incursion", 300);
    assert_eq!(a, b, "same seed must reproduce within a process");
    assert_eq!(a, GOLDEN_RED_TEAM_42, "golden drifted: got {a:#018x}");
}

#[test]
fn test_different_seeds_diverge() {
    assert_ne!(
        run_hash(42, "red-team-incursion", 300),
        run_hash(43, "red-team-incursion", 300)
    );
}

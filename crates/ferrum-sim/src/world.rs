//! The simulated RF world: emitters, seeded noise, simulated time and per-node readouts.
//!
//! # Model
//!
//! * Every emitter has a position, a reference power `tx_dbm` (received power at 1 m, see
//!   [`crate::phys`]), a *native* channel number and a [`EmitterKind`].
//!   Channel numbering per kind: `Esb`/`Carrier`/`Jammer` use nRF24 channels (`2400 + ch` MHz);
//!   `WifiAp`/`Deauth`/`Eapol` use Wi-Fi channels (1-13 = 2.4 GHz, 36..=177 = 5 GHz);
//!   `BleAdv` uses BLE advertising channels 37/38/39.
//! * Each sensor node sits at an anchor (WROOM `(0,0)`, C5 `(6,0)`, S3 `(3,5.2)`) and tunes in
//!   its *own* channel numbering (WROOM: nRF 0..=125, C5: Wi-Fi 2.4/5 GHz, S3: Wi-Fi 2.4 GHz).
//!   A scanner hears an emitter when their occupied bandwidths overlap in frequency.
//! * Readouts ([`RfWorld::rssi_at`], [`RfWorld::rpd_at`]) are pure functions of the emitter set,
//!   the node and the current step's noise seed, so they are stable within a tick and
//!   immediately reflect emitters added or removed by adversaries.
//! * [`RfWorld::step`] advances time, draws a fresh noise seed and generates the sniffable frames.
use crate::phys::{path_loss_dbm, ANCHORS, RSSI_MAX_DBM, RSSI_MIN_DBM};
use ferrum_hal::{FrameKind, FrameMeta};
use ferrum_proto::NodeId;
use rand_core::{Rng, SeedableRng};
use rand_pcg::Pcg64;
use std::collections::VecDeque;

/// RPD asserts when carrier energy exceeds this level (nRF24L01+ spec: -64 dBm).
pub const RPD_THRESHOLD_DBM: i8 = -64;
/// Noise floor (dBm) with no emitters; jitter keeps it within `NOISE_FLOOR_DBM +/- JITTER_DB`.
pub const NOISE_FLOOR_DBM: i8 = -97;
/// Bounded per-sample RSSI jitter (dB).
pub const JITTER_DB: i8 = 2;
/// Weakest raw power (dBm) at which a sniffer can still decode frames.
pub const FRAME_SENSITIVITY_DBM: f32 = -85.0;
/// Per-node cap on queued, not-yet-sniffed frames (oldest are dropped first).
pub const MAX_QUEUED_FRAMES: usize = 4096;
/// Off-centre attenuation (dB per MHz) applied across an emitter's occupied bandwidth.
const OFFSET_DB_PER_MHZ: f32 = 0.5;
/// Cap on frames one emitter generates in one `step` (guards against huge `dt`).
const MAX_FRAMES_PER_EMITTER_STEP: u32 = 1024;
const NODE_COUNT: usize = 3;

/// Kind of RF emitter living in the world. Frame-producing kinds carry their frame rate.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum EmitterKind {
    /// Wi-Fi access point beaconing (`WifiMgmt` frames).
    WifiAp { beacon_fps: u16 },
    /// BLE advertiser (`BleAdv` frames).
    BleAdv { fps: u16 },
    /// nRF24 Enhanced-ShockBurst device, e.g. a wireless keyboard (`Esb` frames).
    Esb { fps: u16 },
    /// 802.11 deauthentication flood (`Deauth` frames).
    Deauth { fps: u16 },
    /// WPA handshake traffic (`Eapol` frames).
    Eapol { fps: u16 },
    /// Narrow continuous carrier (e.g. a ghost-band implant): RPD energy, no frames.
    Carrier,
    /// Wideband jammer (80 MHz wide): pegs RPD across many channels, no frames.
    Jammer,
}

impl EmitterKind {
    /// Frames per second this kind generates (0 for carrier-only kinds).
    pub fn fps(&self) -> u16 {
        match *self {
            Self::WifiAp { beacon_fps } => beacon_fps,
            Self::BleAdv { fps }
            | Self::Esb { fps }
            | Self::Deauth { fps }
            | Self::Eapol { fps } => fps,
            Self::Carrier | Self::Jammer => 0,
        }
    }

    /// The frame class this kind produces, if any.
    pub fn frame_kind(&self) -> Option<FrameKind> {
        match self {
            Self::WifiAp { .. } => Some(FrameKind::WifiMgmt),
            Self::BleAdv { .. } => Some(FrameKind::BleAdv),
            Self::Esb { .. } => Some(FrameKind::Esb),
            Self::Deauth { .. } => Some(FrameKind::Deauth),
            Self::Eapol { .. } => Some(FrameKind::Eapol),
            Self::Carrier | Self::Jammer => None,
        }
    }

    /// Occupied bandwidth in MHz.
    fn bandwidth_mhz(&self) -> f32 {
        match self {
            Self::WifiAp { .. } | Self::Deauth { .. } | Self::Eapol { .. } => 20.0,
            Self::BleAdv { .. } | Self::Esb { .. } => 2.0,
            Self::Carrier => 1.0,
            Self::Jammer => 80.0,
        }
    }
}

/// A point RF source.
///
/// `tx_dbm` is the *received* power at the 1 m reference distance (the reference
/// transmitter of the brain's model is `-40`); `channel` is in the emitter's native numbering
/// (see the module docs).
#[derive(Copy, Clone, Debug, PartialEq)]
pub struct Emitter {
    pub pos: (f32, f32),
    pub tx_dbm: i8,
    pub channel: u8,
    pub kind: EmitterKind,
}

impl Emitter {
    /// Centre frequency in MHz, or `None` for an out-of-range channel.
    pub fn freq_mhz(&self) -> Option<u16> {
        match self.kind {
            EmitterKind::Esb { .. } | EmitterKind::Carrier | EmitterKind::Jammer => {
                nrf_freq_mhz(self.channel)
            }
            EmitterKind::WifiAp { .. } | EmitterKind::Deauth { .. } | EmitterKind::Eapol { .. } => {
                wifi_freq_mhz(self.channel)
            }
            EmitterKind::BleAdv { .. } => match self.channel {
                37 => Some(2402),
                38 => Some(2426),
                39 => Some(2480),
                _ => None,
            },
        }
    }
}

/// Stable handle for an emitter inside an [`RfWorld`].
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub struct EmitterId(pub u32);

/// A frame captured by a simulated sniffer.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct SimFrame {
    pub kind: FrameKind,
    /// The emitter's native channel number.
    pub channel: u8,
    /// RSSI (dBm) at the capturing node.
    pub rssi: i8,
    /// Emitter that sent the frame.
    pub src: EmitterId,
    /// World time (ms) at capture.
    pub t_ms: u64,
}

impl FrameMeta for SimFrame {
    fn kind(&self) -> FrameKind {
        self.kind
    }
    fn channel(&self) -> u8 {
        self.channel
    }
}

fn nrf_freq_mhz(ch: u8) -> Option<u16> {
    (ch <= 125).then(|| 2400 + u16::from(ch))
}

fn wifi_freq_mhz(ch: u8) -> Option<u16> {
    match ch {
        1..=13 => Some(2407 + 5 * u16::from(ch)),
        14 => Some(2484),
        36..=177 => Some(5000 + 5 * u16::from(ch)),
        _ => None,
    }
}

/// Index of a sensor node (`0` WROOM, `1` C5, `2` S3); `None` for non-sensor nodes.
fn node_idx(node: NodeId) -> Option<usize> {
    match node {
        NodeId::WroomDualNrf => Some(0),
        NodeId::Esp32C5Scout => Some(1),
        NodeId::XiaoS3Sense => Some(2),
        _ => None,
    }
}

/// The three sensor nodes in anchor order.
pub const SENSOR_NODES: [NodeId; NODE_COUNT] = [
    NodeId::WroomDualNrf,
    NodeId::Esp32C5Scout,
    NodeId::XiaoS3Sense,
];

/// Anchor position (m) of a sensor node, `None` for non-sensor nodes.
pub fn node_pos(node: NodeId) -> Option<(f32, f32)> {
    node_idx(node).map(|i| ANCHORS[i])
}

/// Centre frequency (MHz) and receive bandwidth (MHz) of `node` tuned to its own channel `ch`.
fn rx_tuning(node: NodeId, ch: u8) -> Option<(u16, f32)> {
    match node {
        NodeId::WroomDualNrf => nrf_freq_mhz(ch).map(|f| (f, 1.0)),
        NodeId::Esp32C5Scout => wifi_freq_mhz(ch).map(|f| (f, 20.0)),
        NodeId::XiaoS3Sense => wifi_freq_mhz(ch).filter(|&f| f < 3000).map(|f| (f, 20.0)),
        _ => None,
    }
}

/// Whether `node`'s sniffer can capture frames of `e`'s kind.
fn node_sniffs(node: NodeId, e: &Emitter) -> bool {
    let wifi_freq = e.freq_mhz().unwrap_or(0);
    match (node, e.kind) {
        (NodeId::WroomDualNrf, EmitterKind::Esb { .. } | EmitterKind::BleAdv { .. }) => true,
        (
            NodeId::Esp32C5Scout,
            EmitterKind::WifiAp { .. } | EmitterKind::Deauth { .. } | EmitterKind::Eapol { .. },
        ) => wifi_freq >= 5000,
        (
            NodeId::XiaoS3Sense,
            EmitterKind::WifiAp { .. } | EmitterKind::Deauth { .. } | EmitterKind::Eapol { .. },
        ) => (1..3000).contains(&wifi_freq),
        (NodeId::XiaoS3Sense, EmitterKind::BleAdv { .. }) => true,
        _ => false,
    }
}

fn dist(a: (f32, f32), b: (f32, f32)) -> f32 {
    ((a.0 - b.0).powi(2) + (a.1 - b.1).powi(2)).sqrt()
}

/// SplitMix64 finaliser: cheap stateless hash for reproducible per-sample jitter.
fn mix64(mut z: u64) -> u64 {
    z = z.wrapping_add(0x9E37_79B9_7F4A_7C15);
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

struct Slot {
    id: EmitterId,
    emitter: Emitter,
    /// Fractional frames carried between steps.
    frac: f32,
}

/// Seeded RF environment. Single-threaded; share between PHYs via
/// [`SharedWorld`](crate::phy_impl::SharedWorld).
pub struct RfWorld {
    time_ms: u64,
    rng: Pcg64,
    noise: u64,
    next_id: u32,
    slots: Vec<Slot>,
    frames: [VecDeque<SimFrame>; NODE_COUNT],
    uplink: VecDeque<(NodeId, Vec<u8>)>,
    downlink: [VecDeque<Vec<u8>>; NODE_COUNT],
}

impl RfWorld {
    /// A quiet world (no emitters) whose every random draw derives from `seed`.
    pub fn new(seed: u64) -> Self {
        let mut rng = Pcg64::seed_from_u64(seed);
        let noise = rng.next_u64();
        Self {
            time_ms: 0,
            rng,
            noise,
            next_id: 0,
            slots: Vec::new(),
            frames: Default::default(),
            uplink: VecDeque::new(),
            downlink: Default::default(),
        }
    }

    /// Simulated time in milliseconds.
    pub fn time_ms(&self) -> u64 {
        self.time_ms
    }

    /// The world's seeded RNG (for adversary models that need reproducible randomness).
    pub fn rng_mut(&mut self) -> &mut Pcg64 {
        &mut self.rng
    }

    // ---- emitters ---------------------------------------------------------------------

    /// Add an emitter; returns its handle.
    pub fn add_emitter(&mut self, emitter: Emitter) -> EmitterId {
        let id = EmitterId(self.next_id);
        self.next_id += 1;
        self.slots.push(Slot {
            id,
            emitter,
            frac: 0.0,
        });
        id
    }

    /// Remove an emitter, returning it if it existed. Remaining emitters keep their order.
    pub fn remove_emitter(&mut self, id: EmitterId) -> Option<Emitter> {
        let i = self.slots.iter().position(|s| s.id == id)?;
        Some(self.slots.remove(i).emitter)
    }

    /// Remove every emitter.
    pub fn clear_emitters(&mut self) {
        self.slots.clear();
    }

    pub fn emitter(&self, id: EmitterId) -> Option<&Emitter> {
        self.slots.iter().find(|s| s.id == id).map(|s| &s.emitter)
    }

    /// Mutable access, e.g. to move an emitter or change its power.
    pub fn emitter_mut(&mut self, id: EmitterId) -> Option<&mut Emitter> {
        self.slots
            .iter_mut()
            .find(|s| s.id == id)
            .map(|s| &mut s.emitter)
    }

    /// All emitters in insertion order.
    pub fn emitters(&self) -> impl Iterator<Item = (EmitterId, &Emitter)> {
        self.slots.iter().map(|s| (s.id, &s.emitter))
    }

    // ---- time + frame generation ------------------------------------------------------

    /// Advance simulated time by `dt_ms`, draw a fresh noise seed and generate the frames
    /// every emitter sent during the interval into the sniffing nodes' queues.
    pub fn step(&mut self, dt_ms: u64) {
        self.time_ms = self.time_ms.saturating_add(dt_ms);
        self.noise = self.rng.next_u64();
        let now = self.time_ms;

        for slot in &mut self.slots {
            let e = slot.emitter;
            let (Some(kind), fps) = (e.kind.frame_kind(), e.kind.fps()) else {
                continue;
            };
            if fps == 0 {
                continue;
            }
            slot.frac += f32::from(fps) * dt_ms as f32 / 1000.0;
            let n = (slot.frac.floor() as u32).min(MAX_FRAMES_PER_EMITTER_STEP);
            slot.frac -= slot.frac.floor();
            for _ in 0..n {
                for (idx, node) in SENSOR_NODES.into_iter().enumerate() {
                    if !node_sniffs(node, &e) {
                        continue;
                    }
                    let raw = path_loss_dbm(e.tx_dbm, dist(e.pos, ANCHORS[idx]));
                    if raw < FRAME_SENSITIVITY_DBM {
                        continue;
                    }
                    // Marginal links lose frames: 0% above -65 dBm up to 90% at -92 dBm.
                    let p_loss = ((-65.0 - raw) / 30.0).clamp(0.0, 0.9);
                    let draw = (self.rng.next_u32() as f32) / (u32::MAX as f32);
                    if draw < p_loss {
                        continue;
                    }
                    let jitter = (self.rng.next_u32() % (2 * JITTER_DB as u32 + 1)) as i32
                        - i32::from(JITTER_DB);
                    let rssi = (raw.round() as i32 + jitter)
                        .clamp(i32::from(RSSI_MIN_DBM), i32::from(RSSI_MAX_DBM))
                        as i8;
                    let q = &mut self.frames[idx];
                    if q.len() >= MAX_QUEUED_FRAMES {
                        q.pop_front();
                    }
                    q.push_back(SimFrame {
                        kind,
                        channel: e.channel,
                        rssi,
                        src: slot.id,
                        t_ms: now,
                    });
                }
            }
        }
    }

    // ---- per-node readouts ------------------------------------------------------------

    /// Strongest emitter power (dBm, unjittered) heard by `node` tuned to its channel `ch`.
    fn signal_dbm(&self, node: NodeId, ch: u8) -> Option<f32> {
        let idx = node_idx(node)?;
        let (rx_f, rx_bw) = rx_tuning(node, ch)?;
        self.slots
            .iter()
            .filter_map(|s| {
                let e = &s.emitter;
                let delta = (f32::from(e.freq_mhz()?) - f32::from(rx_f)).abs();
                if delta > (e.kind.bandwidth_mhz() + rx_bw) / 2.0 {
                    return None;
                }
                Some(path_loss_dbm(e.tx_dbm, dist(e.pos, ANCHORS[idx])) - OFFSET_DB_PER_MHZ * delta)
            })
            .max_by(f32::total_cmp)
    }

    /// Reproducible bounded jitter in `[-JITTER_DB, JITTER_DB]` for this tick's (node, ch).
    fn jitter(&self, node: NodeId, ch: u8) -> i32 {
        let key = self.noise ^ (u64::from(node as u8) << 8) ^ u64::from(ch);
        (mix64(key) % (2 * JITTER_DB as u64 + 1)) as i32 - i32::from(JITTER_DB)
    }

    /// RSSI (dBm) `node` measures on its channel `ch`: the strongest audible emitter (clamped to
    /// `[-90, -25]`) or the jittered noise floor (`<= -95`) when the channel is quiet.
    pub fn rssi_at(&self, node: NodeId, ch: u8) -> i8 {
        let jitter = self.jitter(node, ch);
        match self.signal_dbm(node, ch) {
            Some(p) if p > f32::from(NOISE_FLOOR_DBM) => (p.round() as i32 + jitter)
                .clamp(i32::from(RSSI_MIN_DBM), i32::from(RSSI_MAX_DBM))
                as i8,
            _ => (i32::from(NOISE_FLOOR_DBM) + jitter) as i8,
        }
    }

    /// Received Power Detector: carrier energy above [`RPD_THRESHOLD_DBM`] on `ch`.
    pub fn rpd_at(&self, node: NodeId, ch: u8) -> bool {
        self.rssi_at(node, ch) >= RPD_THRESHOLD_DBM
    }

    /// Pop the next frame `node`'s sniffer captured (oldest first).
    pub fn next_frame(&mut self, node: NodeId) -> Option<SimFrame> {
        self.frames[node_idx(node)?].pop_front()
    }

    /// Frames queued for `node` and not yet sniffed.
    pub fn pending_frames(&self, node: NodeId) -> usize {
        node_idx(node).map_or(0, |i| self.frames[i].len())
    }

    // ---- ESP-NOW mesh (SimTransport backing store) -------------------------------------

    /// A datagram sent by `node` towards the Brain.
    pub fn push_uplink(&mut self, node: NodeId, bytes: &[u8]) {
        self.uplink.push_back((node, bytes.to_vec()));
    }

    /// Next datagram sent by any node towards the Brain.
    pub fn pop_uplink(&mut self) -> Option<(NodeId, Vec<u8>)> {
        self.uplink.pop_front()
    }

    /// Queue a Brain -> node datagram (e.g. a `FerrumPolicyCmd`).
    pub fn push_downlink(&mut self, node: NodeId, bytes: &[u8]) {
        if let Some(i) = node_idx(node) {
            self.downlink[i].push_back(bytes.to_vec());
        }
    }

    /// Next Brain -> node datagram for `node`.
    pub fn pop_downlink(&mut self, node: NodeId) -> Option<Vec<u8>> {
        self.downlink[node_idx(node)?].pop_front()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NODES: [NodeId; 3] = [
        NodeId::WroomDualNrf,
        NodeId::Esp32C5Scout,
        NodeId::XiaoS3Sense,
    ];

    #[test]
    fn test_world_step_advances_time() {
        let mut w = RfWorld::new(1);
        assert_eq!(w.time_ms(), 0);
        w.step(100);
        w.step(250);
        assert_eq!(w.time_ms(), 350);
    }

    #[test]
    fn test_quiet_world_is_quiet() {
        let mut w = RfWorld::new(42);
        for _ in 0..20 {
            w.step(100);
        }
        for node in NODES {
            for ch in 0..=255u8 {
                assert!(!w.rpd_at(node, ch), "{node:?} ch {ch} RPD in a quiet world");
                assert!(
                    w.rssi_at(node, ch) <= -90,
                    "{node:?} ch {ch} loud in a quiet world"
                );
            }
            assert!(
                w.next_frame(node).is_none(),
                "{node:?} sniffed a frame in a quiet world"
            );
        }
    }

    fn ap(pos: (f32, f32), tx: i8, ch: u8, kind: EmitterKind) -> Emitter {
        Emitter {
            pos,
            tx_dbm: tx,
            channel: ch,
            kind,
        }
    }

    #[test]
    fn test_carrier_lights_rpd_only_on_its_channel() {
        let mut w = RfWorld::new(7);
        w.add_emitter(ap((1.0, 0.0), -40, 98, EmitterKind::Carrier));
        w.step(100);
        assert!(w.rpd_at(NodeId::WroomDualNrf, 98));
        assert!(!w.rpd_at(NodeId::WroomDualNrf, 20));
        let peak = w.rssi_at(NodeId::WroomDualNrf, 98);
        assert!((-45..=-35).contains(&peak), "peak {peak}");
        // Wi-Fi-only scanners tune Wi-Fi channels; an nRF carrier at 2498 MHz is out of band.
        assert!(!w.rpd_at(NodeId::XiaoS3Sense, 6));
    }

    #[test]
    fn test_jammer_pegs_many_channels() {
        let mut w = RfWorld::new(7);
        w.add_emitter(ap((3.0, 2.0), -30, 40, EmitterKind::Jammer));
        w.step(100);
        let hot = (0..126u8)
            .filter(|&c| w.rpd_at(NodeId::WroomDualNrf, c))
            .count();
        assert!(hot >= 40, "jammer lit only {hot} channels");
        assert!(w.rpd_at(NodeId::XiaoS3Sense, 6));
    }

    #[test]
    fn test_remove_emitter_quiets_channel() {
        let mut w = RfWorld::new(7);
        let id = w.add_emitter(ap((1.0, 0.0), -40, 98, EmitterKind::Carrier));
        assert!(w.rpd_at(NodeId::WroomDualNrf, 98));
        assert!(w.remove_emitter(id).is_some());
        assert!(!w.rpd_at(NodeId::WroomDualNrf, 98));
        assert!(w.remove_emitter(id).is_none());
    }

    #[test]
    fn test_readout_stable_within_step_and_bounded() {
        let mut w = RfWorld::new(3);
        w.add_emitter(ap((2.0, 1.0), -45, 11, EmitterKind::Carrier));
        let mut seen = std::collections::BTreeSet::new();
        for _ in 0..200 {
            w.step(50);
            let a = w.rssi_at(NodeId::WroomDualNrf, 11);
            assert_eq!(a, w.rssi_at(NodeId::WroomDualNrf, 11));
            seen.insert(a);
        }
        let span = seen.last().unwrap() - seen.first().unwrap();
        assert!(span > 0 && span <= 2 * JITTER_DB, "jitter span {span}");
    }

    #[test]
    fn test_frames_routed_by_band_and_rate() {
        let mut w = RfWorld::new(9);
        // Deauth flood on 5 GHz ch 36 next to the C5; MouseJack keyboard near WROOM; BLE near S3.
        w.add_emitter(ap((6.5, 0.5), -40, 36, EmitterKind::Deauth { fps: 100 }));
        w.add_emitter(ap((0.5, 0.5), -40, 98, EmitterKind::Esb { fps: 20 }));
        w.add_emitter(ap((3.0, 4.5), -40, 37, EmitterKind::BleAdv { fps: 50 }));
        w.step(1000);
        let drain = |w: &mut RfWorld, n| {
            let mut v = Vec::new();
            while let Some(f) = w.next_frame(n) {
                v.push(f);
            }
            v
        };
        let c5 = drain(&mut w, NodeId::Esp32C5Scout);
        assert_eq!(c5.len(), 100);
        assert!(c5
            .iter()
            .all(|f| f.kind() == FrameKind::Deauth && f.channel() == 36));
        let wroom = drain(&mut w, NodeId::WroomDualNrf);
        assert_eq!(
            wroom.iter().filter(|f| f.kind() == FrameKind::Esb).count(),
            20
        );
        assert!(wroom
            .iter()
            .filter(|f| f.kind() == FrameKind::Esb)
            .all(|f| f.channel() == 98));
        let s3 = drain(&mut w, NodeId::XiaoS3Sense);
        assert_eq!(s3.len(), 50);
        assert!(s3.iter().all(|f| f.kind() == FrameKind::BleAdv));
        assert!(w.next_frame(NodeId::Esp32C5Scout).is_none());
    }

    #[test]
    fn test_fractional_rates_accumulate() {
        let mut w = RfWorld::new(9);
        w.add_emitter(ap(
            (6.5, 0.5),
            -40,
            36,
            EmitterKind::WifiAp { beacon_fps: 10 },
        ));
        for _ in 0..100 {
            w.step(10); // 0.1 frame per step
        }
        assert_eq!(w.pending_frames(NodeId::Esp32C5Scout), 10);
    }

    #[test]
    fn test_same_seed_is_reproducible() {
        let run = |seed| {
            let mut w = RfWorld::new(seed);
            w.add_emitter(ap((5.0, 4.0), -50, 6, EmitterKind::Deauth { fps: 300 }));
            w.add_emitter(ap((2.0, 1.0), -45, 98, EmitterKind::Carrier));
            let mut out = Vec::new();
            for _ in 0..10 {
                w.step(100);
                out.push(w.rssi_at(NodeId::WroomDualNrf, 98) as i32);
                out.push(w.rssi_at(NodeId::XiaoS3Sense, 6) as i32);
            }
            let mut frames = Vec::new();
            while let Some(f) = w.next_frame(NodeId::XiaoS3Sense) {
                frames.push(f);
            }
            (out, frames)
        };
        assert_eq!(run(5), run(5));
        assert_ne!(run(5).0, run(6).0);
    }

    #[test]
    fn test_frame_queue_is_bounded() {
        let mut w = RfWorld::new(1);
        w.add_emitter(ap((6.5, 0.5), -40, 36, EmitterKind::Deauth { fps: 10_000 }));
        for _ in 0..10 {
            w.step(1000);
        }
        assert_eq!(w.pending_frames(NodeId::Esp32C5Scout), MAX_QUEUED_FRAMES);
    }

    #[test]
    fn test_mesh_queues() {
        let mut w = RfWorld::new(1);
        w.push_uplink(NodeId::XiaoS3Sense, &[1, 2, 3]);
        assert_eq!(w.pop_uplink(), Some((NodeId::XiaoS3Sense, vec![1, 2, 3])));
        assert_eq!(w.pop_uplink(), None);
        w.push_downlink(NodeId::Esp32C5Scout, &[9, 8]);
        assert_eq!(w.pop_downlink(NodeId::XiaoS3Sense), None);
        assert_eq!(w.pop_downlink(NodeId::Esp32C5Scout), Some(vec![9, 8]));
    }
}

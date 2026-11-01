#![no_std]

//! `ferrum-c5-scout` — Adaptive Unikernel State Machine for **Node 2: ESP32-C5 (4MB Flash, RISC-V)**.
//!
//! Why ESP32-C5 is unique in the swarm:
//! - Only ESP32 with **5 GHz Wi-Fi 6 (`802.11ax`, Channels 36..=165)** + **802.15.4 (`Zigbee` / `Thread`)**.
//! - Tight **384 KB SRAM** ceiling and 4 MB Flash: cannot buffer full PCAP streams across 25+ 5GHz channels
//!   without Ferrum dynamically narrowing the channel hop schedule and offloading 2.4GHz to the S3 Sense.

use ferrum_hal::{
    Clock, FrameKind, FrameMeta, NodeStatus, PacketSniffer, SpectrumScanner, Transport,
};
use ferrum_proto::{FerrumPolicyCmd, NodeId, NodeTelemetry, PolicyMode};

/// Standard 5 GHz UNII-1 / UNII-2 / UNII-3 channels monitored by the ESP32-C5.
pub const WIFI_5GHZ_CHANNELS: [u8; 12] = [36, 40, 44, 48, 52, 56, 60, 64, 149, 153, 157, 165];

/// Sub-mode for the ESP32-C5 radio scheduler.
#[repr(u8)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum C5RadioSchedule {
    /// Sweeps 5GHz + 2.4GHz + Zigbee Ch 15/20/25 with 40ms dwell; Bloom-filter deduplication.
    DualBandSweep = 0x01,
    /// Offloads 2.4GHz to S3 Sense; dedicates 100% radio time to 5GHz UNII-1 & UNII-3 channels.
    Dedicated5GhzLock = 0x02,
    /// Pins to a single 5GHz target channel (e.g. Ch 149) for zero-drop WPA2/WPA3 EAPOL & Deauth capture.
    Surgical5GhzPin = 0x03,
    /// 802.15.4 Zigbee / Thread PAN Coordinator & Key-Transport Auditor.
    ZigbeeThreadAudit = 0x04,
}

pub struct Esp32C5Node {
    pub active_policy: PolicyMode,
    pub schedule: C5RadioSchedule,
    pub pinned_channels: [u8; 4],
    pub current_channel: u8,
    pub dwell_time_ms: u16,
    pub cpu_freq_mhz: u8,
    pub free_sram_kb: u16,
    pub sram_ringbuf_kb: u16,
    pub ringbuf_drops: u16,
    pub wifi_5ghz_mgmt_fps: u16,
    pub deauth_5ghz_cnt: u16,
    pub eapol_5ghz_cnt: u8,
    pub zigbee_pan_fps: u8,
    pub peak_rssi: i8,
}

impl Default for Esp32C5Node {
    fn default() -> Self {
        Self::new()
    }
}

impl Esp32C5Node {
    pub const TOTAL_SRAM_KB: u16 = 384;

    pub const fn new() -> Self {
        Self {
            active_policy: PolicyMode::WideRecon,
            schedule: C5RadioSchedule::DualBandSweep,
            pinned_channels: [36, 44, 149, 157],
            current_channel: 36,
            dwell_time_ms: 40,
            cpu_freq_mhz: 80,
            free_sram_kb: 248,
            sram_ringbuf_kb: 96,
            ringbuf_drops: 0,
            wifi_5ghz_mgmt_fps: 120,
            deauth_5ghz_cnt: 0,
            eapol_5ghz_cnt: 0,
            zigbee_pan_fps: 4,
            peak_rssi: -61,
        }
    }

    /// Applies a `FerrumPolicyCmd` from the Raspberry Pi 5 Ferrum/Laya decision loop.
    pub fn apply_policy_cmd(&mut self, cmd: &FerrumPolicyCmd) {
        if cmd.target_node != (NodeId::Esp32C5Scout as u8)
            && cmd.target_node != (NodeId::Broadcast as u8)
        {
            return;
        }
        if let Some(mode) = PolicyMode::from_u8(cmd.policy_mode) {
            self.active_policy = mode;
            self.schedule = match mode {
                PolicyMode::WideRecon => C5RadioSchedule::DualBandSweep,
                PolicyMode::AnomalyTriage | PolicyMode::FloodJamSurvival => {
                    // When WROOM detects 2.4GHz jamming or anomaly, C5 shifts 100% to 5GHz!
                    C5RadioSchedule::Dedicated5GhzLock
                }
                PolicyMode::SurgicalCapture => C5RadioSchedule::Surgical5GhzPin,
                PolicyMode::TriangulateLock | PolicyMode::SentinelCorrelate => {
                    C5RadioSchedule::Surgical5GhzPin
                }
                PolicyMode::IdsEnforce | PolicyMode::HoneypotLure => {
                    // Full dual-band dwell for the rule engine; decoys live on WROOM.
                    C5RadioSchedule::DualBandSweep
                }
                PolicyMode::ForensicLockdown => {
                    // Pin and preserve: everything C5 hears is evidence now.
                    C5RadioSchedule::Surgical5GhzPin
                }
                PolicyMode::MeshSurvive => {
                    // Degraded duty cycle; features go out over LoRa store-and-forward.
                    C5RadioSchedule::Dedicated5GhzLock
                }
            };
        }
        if cmd.pinned_channels[0] != 0 {
            self.pinned_channels = cmd.pinned_channels;
            self.current_channel = cmd.pinned_channels[0];
        }
        self.dwell_time_ms = cmd.dwell_time_ms.max(10);
        self.cpu_freq_mhz = cmd.cpu_freq_mhz;

        // Dynamically resize SRAM ring buffer while protecting a 64KB floor for RISC-V stack + Wi-Fi MAC
        if self.active_policy == PolicyMode::SurgicalCapture {
            self.sram_ringbuf_kb = 220;
            self.free_sram_kb = Self::TOTAL_SRAM_KB - self.sram_ringbuf_kb - 88;
        } else {
            self.sram_ringbuf_kb = 96;
            self.free_sram_kb = Self::TOTAL_SRAM_KB - self.sram_ringbuf_kb - 68;
        }
    }

    pub fn build_telemetry(&self) -> NodeTelemetry {
        let cpu_load = match self.cpu_freq_mhz {
            240 => 78,
            160 => 54,
            _ => 29,
        };
        let mut t = NodeTelemetry {
            node_id: NodeId::Esp32C5Scout as u8,
            active_policy: self.active_policy as u8,
            sub_policy: self.schedule as u8,
            primary_channel: self.current_channel,
            cpu_load_pct: cpu_load,
            free_sram_kb: self.free_sram_kb,
            free_psram_kb: 0, // ESP32-C5 (4MB Flash) uses internal 384KB SRAM only
            ringbuf_drops: self.ringbuf_drops,
            wifi_mgmt_fps: self.wifi_5ghz_mgmt_fps,
            deauth_disassoc_cnt: self.deauth_5ghz_cnt,
            eapol_handshake_cnt: self.eapol_5ghz_cnt,
            ble_adv_fps: 40,
            bt_classic_inq_cnt: 0,
            ghost_band_hits: 0,
            esb_hid_frames: 0,
            zigbee_pan_frames: self.zigbee_pan_fps,
            peak_anomaly_rssi: self.peak_rssi,
            crc8: 0,
        };
        let bytes = t.to_bytes();
        t.crc8 = bytes[23];
        t
    }
}

/// Minimum SRAM (KB) always reserved for the RISC-V stack + Wi-Fi MAC; the ring buffer never eats it.
pub const SRAM_FLOOR_KB: u16 = 64;
/// Upper bound on frames drained from the sniffer per tick (guards against a never-empty source).
pub const MAX_FRAMES_PER_TICK: usize = 256;
/// RSSI reported when no carrier energy was seen anywhere in the sweep.
pub const QUIET_RSSI_DBM: i8 = -100;

/// Trait-driven ESP32-C5 node agent: the same logic runs on simulated PHYs and real `esp-hal` drivers.
///
/// Each [`tick`](Self::tick) walks the 5 GHz UNII channel schedule through the injected
/// [`SpectrumScanner`] (the whole [`WIFI_5GHZ_CHANNELS`] list, or only the pinned channel in
/// `Surgical5GhzPin`), drains the [`PacketSniffer`] counting Deauth / EAPOL / mgmt frames,
/// enforces the 384 KB SRAM budget, assembles a [`NodeTelemetry`] and relays it over the
/// [`Transport`]. A transport failure degrades to [`NodeStatus::Offline`] instead of panicking.
pub struct C5Agent<S, P, T, C>
where
    S: SpectrumScanner,
    P: PacketSniffer,
    T: Transport,
    C: Clock,
{
    node: Esp32C5Node,
    scanner: S,
    sniffer: P,
    transport: T,
    clock: C,
    last_tick_ms: Option<u64>,
}

impl<S, P, T, C> C5Agent<S, P, T, C>
where
    S: SpectrumScanner,
    P: PacketSniffer,
    P::Frame: FrameMeta,
    T: Transport,
    C: Clock,
{
    pub fn new(scanner: S, sniffer: P, transport: T, clock: C) -> Self {
        Self {
            node: Esp32C5Node::new(),
            scanner,
            sniffer,
            transport,
            clock,
            last_tick_ms: None,
        }
    }

    /// Applies a `FerrumPolicyCmd` from the Pi 5 Brain (ignored if addressed to another node).
    pub fn apply_policy_cmd(&mut self, cmd: &FerrumPolicyCmd) {
        self.node.apply_policy_cmd(cmd);
    }

    /// Clamps the ring buffer so a [`SRAM_FLOOR_KB`] floor always remains, and keeps the
    /// reported free SRAM consistent with the 384 KB total.
    fn enforce_sram_budget(&mut self) {
        let max_ringbuf = Esp32C5Node::TOTAL_SRAM_KB.saturating_sub(SRAM_FLOOR_KB);
        self.node.sram_ringbuf_kb = self.node.sram_ringbuf_kb.min(max_ringbuf);
        let max_free = Esp32C5Node::TOTAL_SRAM_KB.saturating_sub(self.node.sram_ringbuf_kb);
        self.node.free_sram_kb = self.node.free_sram_kb.min(max_free);
    }

    /// One 5 GHz schedule + drain + relay cycle.
    pub fn tick(&mut self) -> NodeStatus {
        let now = self.clock.now_ms();
        let elapsed_ms = self.last_tick_ms.map_or(0, |t| now.saturating_sub(t));
        self.last_tick_ms = Some(now);

        self.enforce_sram_budget();

        // 1. 5 GHz UNII sweep: strongest active channel becomes the tracked channel.
        //    Surgical pin listens on the pinned channel only (zero-drop capture).
        let pinned = [self.node.current_channel];
        let channels: &[u8] = match self.node.schedule {
            C5RadioSchedule::Surgical5GhzPin => &pinned,
            _ => &WIFI_5GHZ_CHANNELS,
        };
        let mut hotspot: Option<(u8, i8)> = None;
        for &ch in channels {
            self.scanner.set_channel(ch);
            if self.scanner.read_rpd() {
                let rssi = self.scanner.sample_rssi();
                if hotspot.is_none_or(|(_, best)| rssi > best) {
                    hotspot = Some((ch, rssi));
                }
            }
        }
        match hotspot {
            Some((ch, rssi)) => {
                self.node.current_channel = ch;
                self.node.peak_rssi = rssi;
            }
            None => self.node.peak_rssi = QUIET_RSSI_DBM,
        }

        // 2. Drain the sniffer into per-window counters.
        let (mut wifi, mut deauth, mut eapol) = (0u32, 0u32, 0u32);
        let mut drained_all = false;
        for _ in 0..MAX_FRAMES_PER_TICK {
            let Some(frame) = self.sniffer.next_frame() else {
                drained_all = true;
                break;
            };
            match frame.kind() {
                FrameKind::WifiMgmt => wifi = wifi.saturating_add(1),
                FrameKind::Deauth => deauth = deauth.saturating_add(1),
                FrameKind::Eapol => eapol = eapol.saturating_add(1),
                FrameKind::Esb | FrameKind::BleAdv => {}
            }
        }
        if !drained_all {
            // Backpressure: the per-tick budget was exhausted with frames still pending.
            self.node.ringbuf_drops = self.node.ringbuf_drops.saturating_add(1);
        }
        // Deauth/disassoc and EAPOL frames are management traffic too.
        let mgmt = wifi.saturating_add(deauth);
        let mgmt_fps = (u64::from(mgmt) * 1000)
            .checked_div(elapsed_ms)
            .unwrap_or(u64::from(mgmt));
        self.node.wifi_5ghz_mgmt_fps = mgmt_fps.min(u64::from(u16::MAX)) as u16;
        self.node.deauth_5ghz_cnt = deauth.min(u32::from(u16::MAX)) as u16;
        self.node.eapol_5ghz_cnt = eapol.min(u32::from(u8::MAX)) as u8;

        // 3. Assemble telemetry. 802.15.4/Zigbee has no source in the promiscuous sniffer
        //    (`FrameKind` is Esb|BleAdv|WifiMgmt|Deauth|Eapol), so report it honestly from the
        //    frames actually captured — zero — rather than the node's constructor placeholder.
        //    Re-seal the CRC after overriding this frame-derived field.
        let mut t = self.node.build_telemetry();
        t.zigbee_pan_frames = 0;
        let bytes = t.to_bytes();
        t.crc8 = bytes[NodeTelemetry::SIZE - 1];

        // 4. Relay; a transport failure means the node is Offline (never panic).
        match self.transport.send(&t.to_bytes()) {
            Ok(()) => NodeStatus::Online(t),
            Err(_) => NodeStatus::Offline,
        }
    }

    /// Current high-level policy mode.
    pub fn active_policy(&self) -> PolicyMode {
        self.node.active_policy
    }

    /// Current radio schedule.
    pub fn schedule(&self) -> C5RadioSchedule {
        self.node.schedule
    }

    /// Currently tracked 5 GHz channel.
    pub fn current_channel(&self) -> u8 {
        self.node.current_channel
    }

    /// Current SRAM ring-buffer allocation in KB.
    pub fn sram_ringbuf_kb(&self) -> u16 {
        self.node.sram_ringbuf_kb
    }

    /// Borrow the transport (useful for tests/simulation inspection).
    pub fn transport(&self) -> &T {
        &self.transport
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ferrum_hal::mock::{MockClock, MockFrame, MockScanner, MockSniffer, MockTransport};
    use ferrum_hal::{FrameKind, NodeStatus};

    fn frame(kind: FrameKind) -> MockFrame {
        MockFrame { channel: 149, kind }
    }

    fn cmd(mode: PolicyMode, pin: u8) -> FerrumPolicyCmd {
        FerrumPolicyCmd {
            target_node: NodeId::Esp32C5Scout as u8,
            policy_mode: mode as u8,
            dual_nrf_mode: 0,
            pinned_channels: [pin, 0, 0, 0],
            dwell_time_ms: 40,
            cpu_freq_mhz: 160,
            s3_psram_pcap_quota_kb: 0,
            crc8: 0,
        }
    }

    #[test]
    fn test_c5_telemetry_from_scanner() {
        let scanner = MockScanner::new().with(149, true, -42);
        let sniffer = MockSniffer::new([
            frame(FrameKind::Deauth),
            frame(FrameKind::Deauth),
            frame(FrameKind::Eapol),
            frame(FrameKind::WifiMgmt),
        ]);
        let mut agent = C5Agent::new(scanner, sniffer, MockTransport::new(), MockClock::new(0));
        match agent.tick() {
            NodeStatus::Online(t) => {
                assert_eq!(t.node_id, NodeId::Esp32C5Scout as u8);
                assert_eq!(t.deauth_disassoc_cnt, 2);
                assert_eq!(t.eapol_handshake_cnt, 1);
                assert!(t.wifi_mgmt_fps > 0);
                assert_eq!(t.primary_channel, 149);
                assert_eq!(t.peak_anomaly_rssi, -42);
            }
            NodeStatus::Offline => panic!("healthy transport must be Online"),
        }
        assert_eq!(agent.current_channel(), 149);
    }

    #[test]
    fn test_c5_offline_on_transport_error() {
        let mut agent = C5Agent::new(
            MockScanner::new().with(36, true, -50),
            MockSniffer::new([frame(FrameKind::Eapol)]),
            MockTransport::failing(),
            MockClock::new(0),
        );
        assert_eq!(agent.tick(), NodeStatus::Offline);
        assert_eq!(agent.tick(), NodeStatus::Offline);
    }

    #[test]
    fn test_c5_relays_valid_telemetry() {
        let mut agent = C5Agent::new(
            MockScanner::new(),
            MockSniffer::new([frame(FrameKind::Deauth)]),
            MockTransport::new(),
            MockClock::new(0),
        );
        let status = agent.tick();
        let mut buf = [0u8; NodeTelemetry::SIZE];
        buf.copy_from_slice(agent.transport().last_sent());
        let decoded = NodeTelemetry::from_bytes(&buf).expect("valid crc");
        assert_eq!(status, NodeStatus::Online(decoded));
    }

    #[test]
    fn test_c5_scans_only_5ghz_unii_channels() {
        // ch 6 (2.4 GHz) is loud but must never be swept; ch 165 (UNII-3) is.
        let mut agent = C5Agent::new(
            MockScanner::new().with(6, true, -20).with(165, true, -70),
            MockSniffer::new([]),
            MockTransport::new(),
            MockClock::new(0),
        );
        let NodeStatus::Online(t) = agent.tick() else {
            panic!("online expected");
        };
        assert_eq!(t.primary_channel, 165);
        assert_eq!(t.peak_anomaly_rssi, -70);
    }

    #[test]
    fn test_c5_surgical_pin_only_listens_on_pinned_channel() {
        let mut agent = C5Agent::new(
            MockScanner::new().with(36, true, -30).with(157, true, -60),
            MockSniffer::new([]),
            MockTransport::new(),
            MockClock::new(0),
        );
        agent.apply_policy_cmd(&cmd(PolicyMode::SurgicalCapture, 157));
        assert_eq!(agent.schedule(), C5RadioSchedule::Surgical5GhzPin);
        let NodeStatus::Online(t) = agent.tick() else {
            panic!("online expected");
        };
        assert_eq!(t.primary_channel, 157);
        assert_eq!(t.peak_anomaly_rssi, -60);
    }

    #[test]
    fn test_c5_sram_budget_guard_holds_floor() {
        let mut agent = C5Agent::new(
            MockScanner::new(),
            MockSniffer::new([]),
            MockTransport::new(),
            MockClock::new(0),
        );
        agent.apply_policy_cmd(&cmd(PolicyMode::SurgicalCapture, 149));
        let NodeStatus::Online(t) = agent.tick() else {
            panic!("online expected");
        };
        assert!(t.free_sram_kb + 64 <= Esp32C5Node::TOTAL_SRAM_KB);
        assert!(agent.sram_ringbuf_kb() + SRAM_FLOOR_KB <= Esp32C5Node::TOTAL_SRAM_KB);
    }

    #[test]
    fn test_c5_survives_flood_jam_failover_on_5ghz() {
        let mut agent = C5Agent::new(
            MockScanner::new().with(44, true, -55),
            MockSniffer::new([frame(FrameKind::Deauth)]),
            MockTransport::new(),
            MockClock::new(0),
        );
        agent.apply_policy_cmd(&cmd(PolicyMode::FloodJamSurvival, 0));
        assert_eq!(agent.schedule(), C5RadioSchedule::Dedicated5GhzLock);
        let NodeStatus::Online(t) = agent.tick() else {
            panic!("C5 must stay online during 2.4 GHz jamming");
        };
        assert_eq!(t.primary_channel, 44);
        assert_eq!(t.deauth_disassoc_cnt, 1);
    }

    #[test]
    fn test_c5_policy_cmd_for_other_node_ignored() {
        let mut agent = C5Agent::new(
            MockScanner::new(),
            MockSniffer::new([]),
            MockTransport::new(),
            MockClock::new(0),
        );
        let mut c = cmd(PolicyMode::SurgicalCapture, 149);
        c.target_node = 0xEE;
        agent.apply_policy_cmd(&c);
        assert_eq!(agent.schedule(), C5RadioSchedule::DualBandSweep);
    }
}

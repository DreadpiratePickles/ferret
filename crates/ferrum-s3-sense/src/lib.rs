#![no_std]

//! `ferrum-s3-sense` — Adaptive Unikernel State Machine for **Node 3: Seeed XIAO ESP32-S3 Sense**.
//!
//! Hardware Capabilities Managed by Ferrum:
//! - **8192 KB (8 MB) Octal PSRAM:** Dynamically partitioned by Ferrum between:
//!   1. `DeepPcapRingBuffer` (up to 7680 KB zero-drop raw 802.11 + EAPOL + BLE packet storage)
//!   2. `ActiveGattAuditCache` (stores enumerated BLE GATT Services & Characteristics of suspect devices)
//!   3. `SensorFusionDma` (OV2640 JPEG framebuffer + PDM Digital Microphone 16kHz FFT audio buffer)
//! - **Privacy-by-Default Hardware Gate:** Camera (`OV2640` PWDN pin) and PDM Microphone clock remain
//!   physically powered down unless Ferrum's Laya engine issues `PolicyMode::SentinelCorrelate`
//!   (triggered when an anomalous RF transmitter breaches `-45 dBm` physical proximity).

use ferrum_hal::{
    Clock, FrameKind, FrameMeta, NodeStatus, PacketSniffer, SpectrumScanner, Transport,
};
use ferrum_proto::{FerrumPolicyCmd, NodeId, NodeTelemetry, PolicyMode};

/// Dynamic 8 MB Octal PSRAM memory partition layout controlled by Ferrum.
#[repr(C)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct S3PsramPartition {
    pub pcap_ringbuf_kb: u16,
    pub ble_gatt_cache_kb: u16,
    pub camera_fb_kb: u16,
    pub pdm_audio_fft_kb: u16,
    pub unallocated_kb: u16,
}

/// Operating sub-mode of the XIAO ESP32-S3 Sense node.
#[repr(u8)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum S3SenseSubMode {
    /// 2.4GHz Ch 1/6/11 PCAP ring buffer (7.5MB PSRAM); Cam & Mic powered OFF.
    DeepPcapBuffer = 0x01,
    /// Connects to a target BLE MAC flagged by the WROOM to enumerate GATT services/characteristics.
    ActiveBleGattAudit = 0x02,
    /// Powers on OV2640 Camera + PDM Mic when target RSSI > -45 dBm to correlate RF with physical presence.
    CamAudioCorrelate = 0x03,
    /// Synchronized 3-node RSSI anchor lock.
    TriangulateAnchorC = 0x04,
}

pub struct XiaoS3SenseNode {
    pub active_policy: PolicyMode,
    pub sub_mode: S3SenseSubMode,
    pub psram: S3PsramPartition,
    pub camera_powered: bool,
    pub pdm_mic_active: bool,
    pub current_channel: u8,
    pub free_sram_kb: u16,
    pub wifi_mgmt_fps: u16,
    pub deauth_cnt: u16,
    pub eapol_captured: u8,
    pub ble_gatt_profiles_dumped: u8,
    pub snapshots_taken: u16,
    pub peak_rssi: i8,
}

impl Default for XiaoS3SenseNode {
    fn default() -> Self {
        Self::new()
    }
}

impl XiaoS3SenseNode {
    pub const TOTAL_SRAM_KB: u16 = 512;
    pub const TOTAL_PSRAM_KB: u16 = 8192;

    pub const fn new() -> Self {
        Self {
            active_policy: PolicyMode::WideRecon,
            sub_mode: S3SenseSubMode::DeepPcapBuffer,
            psram: S3PsramPartition {
                pcap_ringbuf_kb: 7168,
                ble_gatt_cache_kb: 512,
                camera_fb_kb: 0,
                pdm_audio_fft_kb: 0,
                unallocated_kb: 512,
            },
            camera_powered: false,
            pdm_mic_active: false,
            current_channel: 6,
            free_sram_kb: 380,
            wifi_mgmt_fps: 210,
            deauth_cnt: 0,
            eapol_captured: 0,
            ble_gatt_profiles_dumped: 0,
            snapshots_taken: 0,
            peak_rssi: -58,
        }
    }

    /// Reallocates the 8 MB Octal PSRAM and hardware peripheral power domains in response to Ferrum policy.
    pub fn apply_policy_cmd(&mut self, cmd: &FerrumPolicyCmd) {
        if cmd.target_node != (NodeId::XiaoS3Sense as u8)
            && cmd.target_node != (NodeId::Broadcast as u8)
        {
            return;
        }
        if let Some(mode) = PolicyMode::from_u8(cmd.policy_mode) {
            self.active_policy = mode;
            match mode {
                PolicyMode::WideRecon | PolicyMode::FloodJamSurvival => {
                    self.sub_mode = S3SenseSubMode::DeepPcapBuffer;
                    self.camera_powered = false;
                    self.pdm_mic_active = false;
                    self.psram = S3PsramPartition {
                        pcap_ringbuf_kb: 7168,
                        ble_gatt_cache_kb: 512,
                        camera_fb_kb: 0,
                        pdm_audio_fft_kb: 0,
                        unallocated_kb: 512,
                    };
                }
                PolicyMode::AnomalyTriage => {
                    // Active BLE GATT inspection + 2.4GHz Wi-Fi offloading from C5
                    self.sub_mode = S3SenseSubMode::ActiveBleGattAudit;
                    self.camera_powered = false;
                    self.pdm_mic_active = false;
                    self.psram = S3PsramPartition {
                        pcap_ringbuf_kb: 6144,
                        ble_gatt_cache_kb: 1536,
                        camera_fb_kb: 0,
                        pdm_audio_fft_kb: 0,
                        unallocated_kb: 512,
                    };
                }
                PolicyMode::SurgicalCapture => {
                    self.sub_mode = S3SenseSubMode::DeepPcapBuffer;
                    self.camera_powered = false;
                    self.pdm_mic_active = false;
                    let pcap_kb = cmd.s3_psram_pcap_quota_kb.clamp(4096, 7680);
                    self.psram = S3PsramPartition {
                        pcap_ringbuf_kb: pcap_kb,
                        ble_gatt_cache_kb: 256,
                        camera_fb_kb: 0,
                        pdm_audio_fft_kb: 0,
                        unallocated_kb: Self::TOTAL_PSRAM_KB - pcap_kb - 256,
                    };
                }
                PolicyMode::TriangulateLock => {
                    self.sub_mode = S3SenseSubMode::TriangulateAnchorC;
                }
                PolicyMode::SentinelCorrelate => {
                    // Target breached physical proximity (-45 dBm)!
                    // Shrink PCAP ring to 4MB, allocate 3MB to OV2640 JPEG ring + 512KB to PDM Mic FFT!
                    self.sub_mode = S3SenseSubMode::CamAudioCorrelate;
                    self.camera_powered = true;
                    self.pdm_mic_active = true;
                    self.snapshots_taken = self.snapshots_taken.saturating_add(1);
                    self.psram = S3PsramPartition {
                        pcap_ringbuf_kb: 4096,
                        ble_gatt_cache_kb: 512,
                        camera_fb_kb: 2560,
                        pdm_audio_fft_kb: 512,
                        unallocated_kb: 512,
                    };
                }
                PolicyMode::IdsEnforce | PolicyMode::HoneypotLure => {
                    // Full-rate PCAP: the IDS wants everything, and the honeypot records interactions.
                    self.sub_mode = S3SenseSubMode::DeepPcapBuffer;
                    self.camera_powered = false;
                    self.pdm_mic_active = false;
                    self.psram = S3PsramPartition {
                        pcap_ringbuf_kb: 7424,
                        ble_gatt_cache_kb: 256,
                        camera_fb_kb: 0,
                        pdm_audio_fft_kb: 0,
                        unallocated_kb: 512,
                    };
                }
                PolicyMode::ForensicLockdown => {
                    // DMA ring freeze happens in the ISR; here we arm evidence capture.
                    self.sub_mode = S3SenseSubMode::CamAudioCorrelate;
                    self.camera_powered = true;
                    self.pdm_mic_active = true;
                    self.snapshots_taken = self.snapshots_taken.saturating_add(1);
                    self.psram = S3PsramPartition {
                        pcap_ringbuf_kb: 4096,
                        ble_gatt_cache_kb: 256,
                        camera_fb_kb: 2560,
                        pdm_audio_fft_kb: 512,
                        unallocated_kb: 768,
                    };
                }
                PolicyMode::MeshSurvive => {
                    // Minimal buffering; ferrum-triage compresses everything to 12-byte features.
                    self.sub_mode = S3SenseSubMode::DeepPcapBuffer;
                    self.camera_powered = false;
                    self.pdm_mic_active = false;
                    self.psram = S3PsramPartition {
                        pcap_ringbuf_kb: 3072,
                        ble_gatt_cache_kb: 256,
                        camera_fb_kb: 0,
                        pdm_audio_fft_kb: 0,
                        unallocated_kb: 4864,
                    };
                }
            }
        }
        if cmd.pinned_channels[1] != 0 {
            self.current_channel = cmd.pinned_channels[1];
        }
    }

    pub fn build_telemetry(&self) -> NodeTelemetry {
        let mut t = NodeTelemetry {
            node_id: NodeId::XiaoS3Sense as u8,
            active_policy: self.active_policy as u8,
            sub_policy: self.sub_mode as u8,
            primary_channel: self.current_channel,
            cpu_load_pct: if self.camera_powered { 82 } else { 41 },
            free_sram_kb: self.free_sram_kb,
            free_psram_kb: self.psram.unallocated_kb + (self.psram.pcap_ringbuf_kb / 2),
            ringbuf_drops: 0,
            wifi_mgmt_fps: self.wifi_mgmt_fps,
            deauth_disassoc_cnt: self.deauth_cnt,
            eapol_handshake_cnt: self.eapol_captured,
            ble_adv_fps: 195,
            bt_classic_inq_cnt: 0,
            ghost_band_hits: 0,
            esb_hid_frames: 0,
            zigbee_pan_frames: 0,
            peak_anomaly_rssi: self.peak_rssi,
            crc8: 0,
        };
        let bytes = t.to_bytes();
        t.crc8 = bytes[23];
        t
    }
}

/// 2.4 GHz Wi-Fi channels (1..=13) swept by the XIAO ESP32-S3 each tick.
pub const WIFI_24GHZ_CHANNELS: [u8; 13] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13];
/// Upper bound on frames drained from the sniffer per tick (guards against a never-empty source).
pub const MAX_FRAMES_PER_TICK: usize = 256;
/// RSSI reported when no carrier energy was seen anywhere in the sweep.
pub const QUIET_RSSI_DBM: i8 = -100;

/// Trait-driven XIAO ESP32-S3 Sense node agent: the same logic runs on simulated PHYs and real
/// `esp-hal` drivers.
///
/// Each [`tick`](Self::tick) sweeps the 2.4 GHz channels through the injected [`SpectrumScanner`],
/// drains the [`PacketSniffer`] (Wi-Fi mgmt / Deauth / EAPOL / BLE advertisement frames),
/// assembles a [`NodeTelemetry`] reflecting the current 8 MB PSRAM partition and relays it over
/// the [`Transport`]. A transport failure degrades to [`NodeStatus::Offline`] instead of
/// panicking. The PSRAM repartition and camera/mic privacy gate are driven by
/// [`apply_policy_cmd`](Self::apply_policy_cmd), delegating to [`XiaoS3SenseNode`].
pub struct S3Agent<S, P, T, C>
where
    S: SpectrumScanner,
    P: PacketSniffer,
    T: Transport,
    C: Clock,
{
    node: XiaoS3SenseNode,
    scanner: S,
    sniffer: P,
    transport: T,
    clock: C,
    last_tick_ms: Option<u64>,
    ringbuf_drops: u16,
}

impl<S, P, T, C> S3Agent<S, P, T, C>
where
    S: SpectrumScanner,
    P: PacketSniffer,
    P::Frame: FrameMeta,
    T: Transport,
    C: Clock,
{
    pub fn new(scanner: S, sniffer: P, transport: T, clock: C) -> Self {
        Self {
            node: XiaoS3SenseNode::new(),
            scanner,
            sniffer,
            transport,
            clock,
            last_tick_ms: None,
            ringbuf_drops: 0,
        }
    }

    /// Applies a `FerrumPolicyCmd` from the Pi 5 Brain (ignored if addressed to another node).
    /// Drives the PSRAM repartition and the camera / PDM-mic power gate.
    pub fn apply_policy_cmd(&mut self, cmd: &FerrumPolicyCmd) {
        self.node.apply_policy_cmd(cmd);
    }

    /// One 2.4 GHz sweep + drain + relay cycle.
    pub fn tick(&mut self) -> NodeStatus {
        let now = self.clock.now_ms();
        let elapsed_ms = self.last_tick_ms.map_or(0, |t| now.saturating_sub(t));
        self.last_tick_ms = Some(now);

        // 1. 2.4 GHz sweep: strongest active channel becomes the tracked channel.
        let mut hotspot: Option<(u8, i8)> = None;
        for &ch in &WIFI_24GHZ_CHANNELS {
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
        let (mut ble, mut wifi, mut deauth, mut eapol) = (0u32, 0u32, 0u32, 0u32);
        let mut drained_all = false;
        for _ in 0..MAX_FRAMES_PER_TICK {
            let Some(frame) = self.sniffer.next_frame() else {
                drained_all = true;
                break;
            };
            match frame.kind() {
                FrameKind::BleAdv => ble = ble.saturating_add(1),
                FrameKind::WifiMgmt => wifi = wifi.saturating_add(1),
                FrameKind::Deauth => deauth = deauth.saturating_add(1),
                FrameKind::Eapol => eapol = eapol.saturating_add(1),
                FrameKind::Esb => {}
            }
        }
        if !drained_all {
            // Backpressure: the per-tick budget was exhausted with frames still pending.
            self.ringbuf_drops = self.ringbuf_drops.saturating_add(1);
        }
        let per_sec = |n: u32| -> u16 {
            let v = (u64::from(n) * 1000)
                .checked_div(elapsed_ms)
                .unwrap_or(u64::from(n));
            v.min(u64::from(u16::MAX)) as u16
        };
        self.node.wifi_mgmt_fps = per_sec(wifi.saturating_add(deauth));
        self.node.deauth_cnt = deauth.min(u32::from(u16::MAX)) as u16;
        self.node.eapol_captured = eapol.min(u32::from(u8::MAX)) as u8;

        // 3. Assemble + seal telemetry (BLE rate is frame-derived, so re-seal the CRC).
        let mut t = self.node.build_telemetry();
        t.ble_adv_fps = per_sec(ble);
        t.ringbuf_drops = self.ringbuf_drops;
        let t = seal_telemetry(t);

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

    /// Current operating sub-mode.
    pub fn sub_mode(&self) -> S3SenseSubMode {
        self.node.sub_mode
    }

    /// Full 8 MB PSRAM partition layout.
    pub fn psram(&self) -> S3PsramPartition {
        self.node.psram
    }

    /// Deep PCAP ring-buffer allocation in KB.
    pub fn pcap_ringbuf_kb(&self) -> u16 {
        self.node.psram.pcap_ringbuf_kb
    }

    /// OV2640 JPEG framebuffer allocation in KB.
    pub fn camera_fb_kb(&self) -> u16 {
        self.node.psram.camera_fb_kb
    }

    /// PDM microphone FFT buffer allocation in KB.
    pub fn pdm_audio_fft_kb(&self) -> u16 {
        self.node.psram.pdm_audio_fft_kb
    }

    /// Whether the OV2640 camera is powered (privacy gate open).
    pub fn camera_powered(&self) -> bool {
        self.node.camera_powered
    }

    /// Whether the PDM microphone clock is running.
    pub fn pdm_mic_active(&self) -> bool {
        self.node.pdm_mic_active
    }

    /// Currently tracked 2.4 GHz channel.
    pub fn current_channel(&self) -> u8 {
        self.node.current_channel
    }

    /// Borrow the transport (useful for tests/simulation inspection).
    pub fn transport(&self) -> &T {
        &self.transport
    }
}

/// Stamps the integrity checksum into a freshly assembled telemetry frame.
fn seal_telemetry(mut t: NodeTelemetry) -> NodeTelemetry {
    let bytes = t.to_bytes();
    t.crc8 = bytes[NodeTelemetry::SIZE - 1];
    t
}

#[cfg(test)]
mod tests {
    use super::*;
    use ferrum_hal::mock::{MockClock, MockFrame, MockScanner, MockSniffer, MockTransport};
    use ferrum_hal::{FrameKind, NodeStatus};

    fn frame(kind: FrameKind) -> MockFrame {
        MockFrame { channel: 6, kind }
    }

    fn cmd(mode: PolicyMode, pcap_quota_kb: u16) -> FerrumPolicyCmd {
        FerrumPolicyCmd {
            target_node: NodeId::XiaoS3Sense as u8,
            policy_mode: mode as u8,
            dual_nrf_mode: 0,
            pinned_channels: [0, 0, 0, 0],
            dwell_time_ms: 40,
            cpu_freq_mhz: 240,
            s3_psram_pcap_quota_kb: pcap_quota_kb,
            crc8: 0,
        }
    }

    fn agent<const N: usize>(
        sniffer: MockSniffer<N>,
        transport: MockTransport,
    ) -> S3Agent<MockScanner, MockSniffer<N>, MockTransport, MockClock> {
        S3Agent::new(MockScanner::new(), sniffer, transport, MockClock::new(0))
    }

    #[test]
    fn test_s3_psram_repartition_on_lockdown() {
        let mut a = agent(MockSniffer::new([]), MockTransport::new());
        // Privacy-by-default: camera dark, PCAP ring fat.
        assert!(!a.camera_powered());
        assert_eq!(a.camera_fb_kb(), 0);
        assert_eq!(a.pdm_audio_fft_kb(), 0);
        let before = a.pcap_ringbuf_kb();

        a.apply_policy_cmd(&cmd(PolicyMode::ForensicLockdown, 4096));

        assert!(a.camera_powered());
        assert!(a.pdm_mic_active());
        assert!(a.pcap_ringbuf_kb() < before);
        assert_eq!(a.pcap_ringbuf_kb(), 4096);
        assert_eq!(a.camera_fb_kb(), 2560);
        assert_eq!(a.pdm_audio_fft_kb(), 512);
        let p = a.psram();
        assert_eq!(
            p.pcap_ringbuf_kb
                + p.ble_gatt_cache_kb
                + p.camera_fb_kb
                + p.pdm_audio_fft_kb
                + p.unallocated_kb,
            XiaoS3SenseNode::TOTAL_PSRAM_KB
        );
        match a.tick() {
            NodeStatus::Online(t) => assert!(t.free_psram_kb > 0),
            NodeStatus::Offline => panic!("healthy transport must be Online"),
        }

        // SentinelCorrelate takes the same cam/mic path.
        let mut b = agent(MockSniffer::new([]), MockTransport::new());
        b.apply_policy_cmd(&cmd(PolicyMode::SentinelCorrelate, 0));
        assert!(b.camera_powered());
        assert_eq!(b.camera_fb_kb(), 2560);

        // Back to recon: camera powers down, buffers released.
        b.apply_policy_cmd(&cmd(PolicyMode::WideRecon, 0));
        assert!(!b.camera_powered());
        assert_eq!(b.camera_fb_kb(), 0);
    }

    #[test]
    fn test_s3_offline_on_transport_error() {
        let mut a = agent(
            MockSniffer::new([frame(FrameKind::BleAdv)]),
            MockTransport::failing(),
        );
        assert_eq!(a.tick(), NodeStatus::Offline);
        assert_eq!(a.tick(), NodeStatus::Offline);
    }

    #[test]
    fn test_s3_telemetry_from_frames_and_scanner() {
        let scanner = MockScanner::new().with(11, true, -44);
        let sniffer = MockSniffer::new([
            frame(FrameKind::BleAdv),
            frame(FrameKind::BleAdv),
            frame(FrameKind::BleAdv),
            frame(FrameKind::Deauth),
            frame(FrameKind::Eapol),
            frame(FrameKind::WifiMgmt),
        ]);
        let mut a = S3Agent::new(scanner, sniffer, MockTransport::new(), MockClock::new(0));
        let NodeStatus::Online(t) = a.tick() else {
            panic!("online expected");
        };
        assert_eq!(t.node_id, NodeId::XiaoS3Sense as u8);
        assert_eq!(t.ble_adv_fps, 3);
        assert_eq!(t.deauth_disassoc_cnt, 1);
        assert_eq!(t.eapol_handshake_cnt, 1);
        assert_eq!(t.primary_channel, 11);
        assert_eq!(t.peak_anomaly_rssi, -44);
        let mut buf = [0u8; NodeTelemetry::SIZE];
        buf.copy_from_slice(a.transport().last_sent());
        assert_eq!(NodeTelemetry::from_bytes(&buf), Some(t));
    }

    #[test]
    fn test_s3_policy_cmd_for_other_node_ignored() {
        let mut a = agent(MockSniffer::new([]), MockTransport::new());
        let mut c = cmd(PolicyMode::ForensicLockdown, 4096);
        c.target_node = 0xEE;
        a.apply_policy_cmd(&c);
        assert!(!a.camera_powered());
    }
}

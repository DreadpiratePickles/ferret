#![no_std]

//! `ferrum-wroom-nrf` — Adaptive Unikernel/Bare-Metal Driver for **Node 1: ESP32-WROOM + Dual nRF24L01+**.
//!
//! Hardware Topology on the ESP32-WROOM Dual-nRF24 Expansion Shield:
//! - **Core 0 (`PRO_CPU`):** Internal 2.4 GHz Radio running:
//!   - Bluetooth Classic (`BR/EDR`) Inquiry Scanner (unique to original ESP32-WROOM LX6!)
//!   - BLE 4.2 Advertising Sniffer (Ch 39 / `2480 MHz`) + Passive MAC-Randomization Fingerprinter
//!   - ESP-NOW Mesh Backhaul to the Raspberry Pi 5 Ferrum Brain
//! - **Core 1 (`APP_CPU`):** Dedicated zero-jitter SPI loop driving TWO independent nRF24L01+ PA/LNA modules:
//!   - **nRF24 #1 (`VSPI` / `SPI3`):** `SCK=18, MISO=19, MOSI=23, CSN=21, CE=22`
//!   - **nRF24 #2 (`HSPI` / `SPI2`):** `SCK=14, MISO=12, MOSI=13, CSN=15, CE=16`

use ferrum_hal::{
    Clock, FrameKind, FrameMeta, NodeStatus, PacketSniffer, SpectrumScanner, Transport,
};
use ferrum_proto::{
    BleDeviceFingerprint, DualNrfPolicy, FerrumPolicyCmd, NodeId, NodeTelemetry, NrfSpectrumBitmap,
    PolicyMode,
};

/// Default GPIO Pinout for the AliExpress ESP32-WROOM Dual-nRF24L01+ Shield.
#[derive(Copy, Clone, Debug)]
pub struct DualNrfPinout {
    pub nrf1_vspi_sck: u8,
    pub nrf1_vspi_miso: u8,
    pub nrf1_vspi_mosi: u8,
    pub nrf1_vspi_csn: u8,
    pub nrf1_vspi_ce: u8,
    pub nrf2_hspi_sck: u8,
    pub nrf2_hspi_miso: u8,
    pub nrf2_hspi_mosi: u8,
    pub nrf2_hspi_csn: u8,
    pub nrf2_hspi_ce: u8,
}

impl DualNrfPinout {
    pub const STANDARD_SHIELD: Self = Self {
        nrf1_vspi_sck: 18,
        nrf1_vspi_miso: 19,
        nrf1_vspi_mosi: 23,
        nrf1_vspi_csn: 21,
        nrf1_vspi_ce: 22,
        nrf2_hspi_sck: 14,
        nrf2_hspi_miso: 12,
        nrf2_hspi_mosi: 13,
        nrf2_hspi_csn: 15,
        nrf2_hspi_ce: 16,
    };
}

/// nRF24L01+ Hardware Register Map (SPI Commands & Registers).
///
/// Phase-2 firmware driver surface — not used by the Phase-1 simulated agent. This register map,
/// together with [`Nrf24Hal`] and [`configure_nrf_promiscuous_sniffer`], is the scaffolding the
/// `esp-hal` SPI driver will fill in; the simulated [`WroomAgent`] drives the radios through the
/// `ferrum-hal` traits instead.
pub mod nrf_regs {
    pub const CMD_R_REGISTER: u8 = 0x00;
    pub const CMD_W_REGISTER: u8 = 0x20;
    pub const CMD_R_RX_PAYLOAD: u8 = 0x61;
    pub const CMD_FLUSH_RX: u8 = 0xE2;

    pub const REG_CONFIG: u8 = 0x00;
    pub const REG_EN_AA: u8 = 0x01;
    pub const REG_EN_RXADDR: u8 = 0x02;
    pub const REG_SETUP_AW: u8 = 0x03;
    pub const REG_RF_CH: u8 = 0x05;
    pub const REG_RF_SETUP: u8 = 0x06;
    pub const REG_STATUS: u8 = 0x07;
    pub const REG_RPD: u8 = 0x09; // Received Power Detector (Bit 0 = 1 when carrier > -64 dBm)
    pub const REG_RX_ADDR_P0: u8 = 0x0A;
    pub const REG_RX_PW_P0: u8 = 0x11;
}

/// Hardware abstraction trait for an individual nRF24L01+ transceiver over SPI (`esp-hal` or mock).
///
/// Phase-2 firmware driver surface — not used by the Phase-1 simulated agent.
pub trait Nrf24Hal {
    fn write_reg(&mut self, reg: u8, val: u8);
    fn write_reg_buf(&mut self, reg: u8, bytes: &[u8]);
    fn read_reg(&mut self, reg: u8) -> u8;
    fn read_rx_payload(&mut self, out: &mut [u8; 32]) -> bool;
    fn set_ce(&mut self, high: bool);
    fn delay_us(&mut self, micros: u32);
}

/// Configures an nRF24L01+ into **Promiscuous Enhanced ShockBurst (ESB) / GFSK Sniffer Mode**.
///
/// Phase-2 firmware driver surface — not used by the Phase-1 simulated agent.
///
/// Uses the classic illegal `SETUP_AW = 0x00` (2-byte address width) with `0xAA55` alternating
/// preamble bytes and `EN_AA = 0x00`, `CRC = disabled` so the radio shifts raw demodulated GFSK
/// frames (MouseJack wireless keyboards/mice, drone RC links, raw BLE advertising bits) into RX FIFO.
pub fn configure_nrf_promiscuous_sniffer<H: Nrf24Hal>(
    radio: &mut H,
    channel: u8,
    rate_2mbps: bool,
) {
    radio.set_ce(false);
    // Power up in PRX mode (PRIM_RX = 1, PWR_UP = 1, CRC disabled = 0)
    radio.write_reg(nrf_regs::REG_CONFIG, 0x03);
    // Disable ShockBurst Auto-Acknowledge on all pipes
    radio.write_reg(nrf_regs::REG_EN_AA, 0x00);
    // Enable Pipe 0
    radio.write_reg(nrf_regs::REG_EN_RXADDR, 0x01);
    // Illegal 2-byte address width trick (`0x00`) to trigger on 0xAA / 0x55 GFSK preamble
    radio.write_reg(nrf_regs::REG_SETUP_AW, 0x00);
    radio.write_reg_buf(nrf_regs::REG_RX_ADDR_P0, &[0xAA, 0x55]);
    // Capture maximum 32-byte raw payload window
    radio.write_reg(nrf_regs::REG_RX_PW_P0, 32);
    // Set data rate (2Mbps for ESB/MouseJack, 1Mbps for BLE raw Ch 37/38/39) + Max LNA gain
    let rf_setup = if rate_2mbps { 0x0F } else { 0x07 };
    radio.write_reg(nrf_regs::REG_RF_SETUP, rf_setup);
    radio.write_reg(nrf_regs::REG_RF_CH, channel.min(125));
    radio.set_ce(true);
    radio.delay_us(130); // PLL settling time
}

/// State machine running on the **ESP32-WROOM + Dual nRF24L01+** node.
pub struct WroomDualNrfNode {
    pub active_policy: PolicyMode,
    pub dual_nrf_policy: DualNrfPolicy,
    pub spectrum: NrfSpectrumBitmap,
    pub sram_free_kb: u16,
    pub cpu_load_pct: u8,
    pub bt_classic_devices: u8,
    pub ble_adv_fps: u16,
    pub deauth_cnt: u16,
    pub esb_frames_captured: u8,
    pub last_hotspot_nrf_ch: u8,
    pub peak_rssi: i8,
}

impl Default for WroomDualNrfNode {
    fn default() -> Self {
        Self::new()
    }
}

impl WroomDualNrfNode {
    pub const TOTAL_SRAM_KB: u16 = 520;

    pub const fn new() -> Self {
        Self {
            active_policy: PolicyMode::WideRecon,
            dual_nrf_policy: DualNrfPolicy::SplitSpectrumWaterfall,
            spectrum: NrfSpectrumBitmap::empty(),
            sram_free_kb: 390,
            cpu_load_pct: 32,
            bt_classic_devices: 0,
            ble_adv_fps: 85,
            deauth_cnt: 0,
            esb_frames_captured: 0,
            last_hotspot_nrf_ch: 2,
            peak_rssi: -68,
        }
    }

    /// Applies a 13-byte `FerrumPolicyCmd` dispatched from the Raspberry Pi 5 Ferrum/Laya Brain.
    pub fn apply_policy_cmd(&mut self, cmd: &FerrumPolicyCmd) {
        if cmd.target_node != (NodeId::WroomDualNrf as u8)
            && cmd.target_node != (NodeId::Broadcast as u8)
        {
            return;
        }
        if let Some(mode) = PolicyMode::from_u8(cmd.policy_mode) {
            self.active_policy = mode;
        }
        self.dual_nrf_policy = match cmd.dual_nrf_mode {
            0x01 => DualNrfPolicy::SplitSpectrumWaterfall,
            0x02 => DualNrfPolicy::HunterKillerEsb,
            0x03 => DualNrfPolicy::Simultaneous3ChBle,
            0x04 => DualNrfPolicy::Layer1JamTriage,
            _ => self.dual_nrf_policy,
        };
        if cmd.pinned_channels[0] != 0 {
            self.last_hotspot_nrf_ch = cmd.pinned_channels[0].min(125);
        }
    }

    /// Generates the 24-byte `NodeTelemetry` frame for ESP-NOW transmission to the Pi 5.
    pub fn build_telemetry(&self) -> NodeTelemetry {
        let t = NodeTelemetry {
            node_id: NodeId::WroomDualNrf as u8,
            active_policy: self.active_policy as u8,
            sub_policy: self.dual_nrf_policy as u8,
            primary_channel: self.last_hotspot_nrf_ch,
            cpu_load_pct: self.cpu_load_pct,
            free_sram_kb: self.sram_free_kb,
            free_psram_kb: 0, // WROOM has no PSRAM
            ringbuf_drops: 0,
            wifi_mgmt_fps: 95,
            deauth_disassoc_cnt: self.deauth_cnt,
            eapol_handshake_cnt: 0,
            ble_adv_fps: self.ble_adv_fps,
            bt_classic_inq_cnt: self.bt_classic_devices,
            ghost_band_hits: self.spectrum.ghost_band_active_count(),
            esb_hid_frames: self.esb_frames_captured,
            zigbee_pan_frames: 0,
            peak_anomaly_rssi: self.peak_rssi,
            crc8: 0,
        };
        seal_telemetry(t)
    }
}

/// Stamps the integrity checksum into a freshly assembled telemetry frame.
fn seal_telemetry(mut t: NodeTelemetry) -> NodeTelemetry {
    let bytes = t.to_bytes();
    t.crc8 = bytes[NodeTelemetry::SIZE - 1];
    t
}

/// Number of nRF24L01+ RF channels swept per cycle (`2400..=2525 MHz`).
pub const NRF_CHANNEL_COUNT: u8 = 126;
/// RSSI reported when no carrier energy was seen anywhere in the sweep.
pub const QUIET_RSSI_DBM: i8 = -100;
/// Upper bound on frames drained from the sniffer per tick (guards against a never-empty source).
pub const MAX_FRAMES_PER_TICK: usize = 256;

/// Trait-driven WROOM node agent: the same logic runs on simulated PHYs and real `esp-hal` drivers.
///
/// Each [`tick`](Self::tick) sweeps the 126 nRF channels through the injected
/// [`SpectrumScanner`], drains the [`PacketSniffer`], assembles a [`NodeTelemetry`]
/// and relays it over the [`Transport`]. A transport failure degrades to
/// [`NodeStatus::Offline`] instead of panicking.
pub struct WroomAgent<S, P, T, C>
where
    S: SpectrumScanner,
    P: PacketSniffer,
    T: Transport,
    C: Clock,
{
    node: WroomDualNrfNode,
    scanner: S,
    sniffer: P,
    transport: T,
    clock: C,
    last_tick_ms: Option<u64>,
}

impl<S, P, T, C> WroomAgent<S, P, T, C>
where
    S: SpectrumScanner,
    P: PacketSniffer,
    P::Frame: FrameMeta,
    T: Transport,
    C: Clock,
{
    pub fn new(scanner: S, sniffer: P, transport: T, clock: C) -> Self {
        Self {
            node: WroomDualNrfNode::new(),
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

    /// One sweep + triage + relay cycle.
    ///
    /// The scanner sweeps all 126 channels sequentially (the split-spectrum
    /// parallelism across the two physical nRFs lives in the scanner implementation).
    pub fn tick(&mut self) -> NodeStatus {
        let now = self.clock.now_ms();
        let elapsed_ms = self.last_tick_ms.map_or(0, |t| now.saturating_sub(t));
        self.last_tick_ms = Some(now);

        // 1. Spectrum sweep: RPD per channel; strongest active channel becomes the hotspot.
        let mut spectrum = NrfSpectrumBitmap::empty();
        let mut hotspot: Option<(u8, i8)> = None;
        for ch in 0..NRF_CHANNEL_COUNT {
            self.scanner.set_channel(ch);
            if self.scanner.read_rpd() {
                spectrum.set_channel(ch, true);
                let rssi = self.scanner.sample_rssi();
                if hotspot.is_none_or(|(_, best)| rssi > best) {
                    hotspot = Some((ch, rssi));
                }
            }
        }
        self.node.spectrum = spectrum;
        match hotspot {
            Some((ch, rssi)) => {
                self.node.last_hotspot_nrf_ch = ch;
                self.node.peak_rssi = rssi;
            }
            None => self.node.peak_rssi = QUIET_RSSI_DBM,
        }

        // 2. Drain the sniffer into per-window counters.
        let (mut esb, mut ble, mut wifi, mut deauth, mut eapol) = (0u32, 0u32, 0u32, 0u32, 0u32);
        for _ in 0..MAX_FRAMES_PER_TICK {
            let Some(frame) = self.sniffer.next_frame() else {
                break;
            };
            match frame.kind() {
                FrameKind::Esb => esb += 1,
                FrameKind::BleAdv => ble += 1,
                FrameKind::WifiMgmt => wifi += 1,
                FrameKind::Deauth => deauth += 1,
                FrameKind::Eapol => eapol += 1,
            }
        }
        let per_sec = |n: u32| -> u16 {
            let v = (u64::from(n) * 1000)
                .checked_div(elapsed_ms)
                .unwrap_or(u64::from(n));
            v.min(u64::from(u16::MAX)) as u16
        };
        self.node.esb_frames_captured = esb.min(u32::from(u8::MAX)) as u8;
        self.node.ble_adv_fps = per_sec(ble);
        self.node.deauth_cnt = deauth.min(u32::from(u16::MAX)) as u16;

        // 3. Assemble + seal telemetry.
        let mut t = self.node.build_telemetry();
        t.wifi_mgmt_fps = per_sec(wifi);
        t.eapol_handshake_cnt = eapol.min(u32::from(u8::MAX)) as u8;
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

    /// Current dual-nRF sub-policy.
    pub fn dual_nrf_policy(&self) -> DualNrfPolicy {
        self.node.dual_nrf_policy
    }

    /// Spectrum bitmap from the most recent sweep.
    pub fn spectrum(&self) -> &NrfSpectrumBitmap {
        &self.node.spectrum
    }

    /// Borrow the transport (useful for tests/simulation inspection).
    pub fn transport(&self) -> &T {
        &self.transport
    }
}

/// Passive BLE MAC-Randomization De-Anonymizer (`#![no_std]`).
///
/// Modern iOS/Android devices randomize their 6-byte BLE MAC every ~15 minutes,
/// but the **ordered TLV structure of their Advertising Data (AD) elements**
/// (e.g., Flags `0x01`, TX Power `0x0A`, Service UUIDs `0x03`/`0x16`, Manufacturer ID `0xFF`
/// with sub-type header & length, plus advertising interval $\Delta t$ bucket) remains invariant.
///
/// This function computes a 32-bit FNV-1a structural signature over the invariant fields
/// while stripping volatile random tokens/MAC bytes.
pub fn compute_ble_structural_fingerprint(
    raw_adv_pdu: &[u8],
    adv_interval_ms: u16,
) -> (u32, u16, bool) {
    let mut hash: u32 = 0x811c_9dc5;
    let mut company_id: u16 = 0x0000;
    let mut is_spam_signature = false;

    let mut idx = 0usize;
    while idx < raw_adv_pdu.len() {
        let ad_len = raw_adv_pdu[idx] as usize;
        if ad_len == 0 || idx + 1 + ad_len > raw_adv_pdu.len() {
            break;
        }
        let ad_type = raw_adv_pdu[idx + 1];
        let payload = &raw_adv_pdu[idx + 2..idx + 1 + ad_len];

        // Hash the AD type and element length (structural shape)
        hash ^= ad_type as u32;
        hash = hash.wrapping_mul(0x0100_0193);
        hash ^= (ad_len as u32) & 0xFF;
        hash = hash.wrapping_mul(0x0100_0193);

        // Manufacturer Specific Data (0xFF)
        if ad_type == 0xFF && payload.len() >= 2 {
            company_id = u16::from_le_bytes([payload[0], payload[1]]);
            hash ^= company_id as u32;
            hash = hash.wrapping_mul(0x0100_0193);

            // Hash the sub-TLV type & length byte (e.g. Apple Continuity 0x004C nearby/handoff header)
            // while ignoring the rotating random auth tag bytes at the tail!
            if payload.len() >= 4 {
                let sub_type = payload[2];
                let sub_len = payload[3];
                hash ^= ((sub_type as u32) << 8) | (sub_len as u32);
                hash = hash.wrapping_mul(0x0100_0193);

                // Detect Flipper Zero / SourApple / SwiftPair spoofed pop-up spam frames
                if (company_id == 0x004C
                    && (sub_type == 0x0F || sub_type == 0x07)
                    && adv_interval_ms < 25)
                    || (company_id == 0x0006 && adv_interval_ms < 20)
                {
                    is_spam_signature = true;
                }
            }
        } else if ad_type == 0x0A && !payload.is_empty() {
            // TX Power Level (invariant per hardware radio profile)
            hash ^= payload[0] as u32;
            hash = hash.wrapping_mul(0x0100_0193);
        }

        idx += 1 + ad_len;
    }

    // Quantize advertising interval into 10ms buckets so jitter doesn't alter the hash
    let interval_bucket = (adv_interval_ms / 10) as u32;
    hash ^= interval_bucket;
    hash = hash.wrapping_mul(0x0100_0193);

    (hash, company_id, is_spam_signature)
}

/// Builds a `BleDeviceFingerprint` from a captured BLE advertisement and 3-anchor RSSI readings.
pub fn build_ble_fingerprint(
    mac: [u8; 6],
    raw_adv_pdu: &[u8],
    adv_interval_ms: u16,
    anchor_rssi: [i8; 3],
) -> BleDeviceFingerprint {
    let (structural_hash, company_id, is_ble_spam) =
        compute_ble_structural_fingerprint(raw_adv_pdu, adv_interval_ms);
    BleDeviceFingerprint {
        current_mac: mac,
        structural_hash,
        adv_interval_units: (adv_interval_ms * 10) / 6,
        company_id,
        anchor_rssi,
        is_ble_spam,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ble_mac_rotation_preserves_structural_fingerprint() {
        // Simulated Apple Continuity frame before MAC rotation (random tail bytes: 0x11, 0x22, 0x33)
        let pdu_before: [u8; 14] = [
            0x02, 0x01, 0x1A, // Flags
            0x02, 0x0A, 0x0C, // TX Power = +12 dBm
            0x07, 0xFF, 0x4C, 0x00, 0x10, 0x05, 0x11,
            0x22, // Apple 0x004C sub-type 0x10 len 0x05
        ];
        // 15 minutes later: phone rotates MAC and rotates Continuity random token bytes (0x99, 0xFE)
        let pdu_after: [u8; 14] = [
            0x02, 0x01, 0x1A, 0x02, 0x0A, 0x0C, 0x07, 0xFF, 0x4C, 0x00, 0x10, 0x05, 0x99, 0xFE,
        ];

        let fp1 = build_ble_fingerprint(
            [0x5A, 0x12, 0x34, 0xAA, 0xBB, 0x01],
            &pdu_before,
            102,
            [-48, -62, -55],
        );
        let fp2 = build_ble_fingerprint(
            [0x7E, 0x98, 0x11, 0xCC, 0xDD, 0x99],
            &pdu_after,
            104,
            [-46, -60, -53],
        );

        assert_ne!(fp1.current_mac, fp2.current_mac);
        assert_eq!(
            fp1.structural_hash, fp2.structural_hash,
            "Structural hash tracks same device across MAC rotation!"
        );
        assert_eq!(fp1.company_id, 0x004C);
        assert!(!fp1.is_ble_spam);
    }

    use ferrum_hal::mock::{
        FrameKind, MockClock, MockFrame, MockScanner, MockSniffer, MockTransport,
    };
    use ferrum_hal::NodeStatus;

    fn frame(kind: FrameKind) -> MockFrame {
        MockFrame { channel: 95, kind }
    }

    #[test]
    fn test_agent_builds_telemetry_from_scanner() {
        // Ghost-band hit on nRF ch 110 (2510 MHz) + two MouseJack-style ESB frames.
        let scanner = MockScanner::new().with(110, true, -34);
        let sniffer = MockSniffer::new([frame(FrameKind::Esb), frame(FrameKind::Esb)]);
        let mut agent = WroomAgent::new(scanner, sniffer, MockTransport::new(), MockClock::new(0));

        match agent.tick() {
            NodeStatus::Online(t) => {
                assert!(t.ghost_band_hits > 0, "ghost band hit must be reported");
                assert!(t.esb_hid_frames > 0, "ESB frames must be counted");
                assert_eq!(t.node_id, NodeId::WroomDualNrf as u8);
                assert_eq!(t.primary_channel, 110);
                assert_eq!(t.peak_anomaly_rssi, -34);
            }
            NodeStatus::Offline => panic!("healthy transport must be Online"),
        }
    }

    #[test]
    fn test_agent_relays_telemetry_over_transport() {
        let mut agent = WroomAgent::new(
            MockScanner::new(),
            MockSniffer::new([frame(FrameKind::Deauth)]),
            MockTransport::new(),
            MockClock::new(0),
        );
        let status = agent.tick();
        let sent = agent.transport().last_sent();
        assert_eq!(sent.len(), NodeTelemetry::SIZE);
        let mut buf = [0u8; NodeTelemetry::SIZE];
        buf.copy_from_slice(sent);
        let decoded = NodeTelemetry::from_bytes(&buf).expect("valid crc");
        assert_eq!(status, NodeStatus::Online(decoded));
        assert_eq!(decoded.deauth_disassoc_cnt, 1);
    }

    #[test]
    fn test_agent_offline_on_transport_error() {
        let mut agent = WroomAgent::new(
            MockScanner::new().with(110, true, -34),
            MockSniffer::new([frame(FrameKind::Esb)]),
            MockTransport::failing(),
            MockClock::new(0),
        );
        // Must not panic, and must degrade to Offline.
        assert_eq!(agent.tick(), NodeStatus::Offline);
        // Still usable on the next tick (no poisoned state).
        assert_eq!(agent.tick(), NodeStatus::Offline);
    }

    #[test]
    fn test_agent_sweeps_all_126_channels_and_resets_each_tick() {
        let mut agent = WroomAgent::new(
            MockScanner::new().with(0, true, -50).with(125, true, -60),
            MockSniffer::new([]),
            MockTransport::new(),
            MockClock::new(0),
        );
        let NodeStatus::Online(t) = agent.tick() else {
            panic!("online expected");
        };
        // ch 125 is in the ghost band; ch 0 is not.
        assert_eq!(t.ghost_band_hits, 1);
        assert!(agent.spectrum().get_channel(0));
        assert!(agent.spectrum().get_channel(125));
    }

    #[test]
    fn test_agent_policy_cmd_targets_wroom_only() {
        let mut agent = WroomAgent::new(
            MockScanner::new(),
            MockSniffer::new([]),
            MockTransport::new(),
            MockClock::new(0),
        );
        let mut cmd = FerrumPolicyCmd {
            target_node: NodeId::WroomDualNrf as u8,
            policy_mode: PolicyMode::SurgicalCapture as u8,
            dual_nrf_mode: 0x02,
            pinned_channels: [0; 4],
            dwell_time_ms: 250,
            cpu_freq_mhz: 240,
            s3_psram_pcap_quota_kb: 0,
            crc8: 0,
        };
        agent.apply_policy_cmd(&cmd);
        assert_eq!(agent.dual_nrf_policy(), DualNrfPolicy::HunterKillerEsb);
        cmd.target_node = 0xEE; // someone else's command is ignored
        cmd.dual_nrf_mode = 0x04;
        agent.apply_policy_cmd(&cmd);
        assert_eq!(agent.dual_nrf_policy(), DualNrfPolicy::HunterKillerEsb);
    }
}

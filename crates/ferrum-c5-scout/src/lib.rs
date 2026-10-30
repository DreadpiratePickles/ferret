#![no_std]

//! `ferrum-c5-scout` — Adaptive Unikernel State Machine for **Node 2: ESP32-C5 (4MB Flash, RISC-V)**.
//!
//! Why ESP32-C5 is unique in the swarm:
//! - Only ESP32 with **5 GHz Wi-Fi 6 (`802.11ax`, Channels 36..=165)** + **802.15.4 (`Zigbee` / `Thread`)**.
//! - Tight **384 KB SRAM** ceiling and 4 MB Flash: cannot buffer full PCAP streams across 25+ 5GHz channels
//!   without Ferrum dynamically narrowing the channel hop schedule and offloading 2.4GHz to the S3 Sense.

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

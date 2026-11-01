#![no_std]

//! `ferrum-proto` — Zero-allocation `#![no_std]` wire protocol shared across:
//! - Node 1: `ESP32-WROOM` + Dual `nRF24L01+` (VSPI + HSPI) + BT Classic (BR/EDR) + BLE 4.2
//! - Node 2: `ESP32-C5` (4MB Flash, RISC-V) — 5 GHz Wi-Fi 6 + 2.4 GHz + 802.15.4 (Zigbee/Thread)
//! - Node 3: `XIAO ESP32-S3 Sense` (8MB PSRAM) — 2.4 GHz Deep PCAP + Active BLE GATT + Cam/PDM Mic
//! - Control Plane: `Raspberry Pi 5 (8GB)` running Ferrum + Laya System-1 Decision Engine
//! - Operator Deck: `ClockworkPi uConsole` with HackerGadgets AIOv2 (RTL-SDR + LoRa SX1262)

/// Maximum payload of a single connectionless ESP-NOW action frame.
pub const ESP_NOW_MAX_PAYLOAD: usize = 250;

/// Hardware Node Identifiers in the CyberSwarm.
#[repr(u8)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum NodeId {
    WroomDualNrf = 0x01,
    Esp32C5Scout = 0x02,
    XiaoS3Sense = 0x03,
    UConsoleAio2 = 0x04,
    Pi5Brain = 0xFE,
    Broadcast = 0xFF,
}

impl NodeId {
    pub const fn from_u8(v: u8) -> Option<Self> {
        match v {
            0x01 => Some(Self::WroomDualNrf),
            0x02 => Some(Self::Esp32C5Scout),
            0x03 => Some(Self::XiaoS3Sense),
            0x04 => Some(Self::UConsoleAio2),
            0xFE => Some(Self::Pi5Brain),
            0xFF => Some(Self::Broadcast),
            _ => None,
        }
    }
}

/// High-level Ferrum Unikernel / Edge Resource Policy Modes selected by Laya.
#[repr(u8)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum PolicyMode {
    /// Low-power wide spectrum sweep; Bloom-filter deduplication; Camera/Mic off.
    WideRecon = 0x01,
    /// Cooperative band split: C5 locks 5GHz, S3 takes 2.4GHz, WROOM sweeps BT + Ghost Band.
    AnomalyTriage = 0x02,
    /// Single-channel pin @ 240MHz; zero-drop PSRAM ring buffer; raw EAPOL/ESB frame streaming.
    SurgicalCapture = 0x03,
    /// Layer-1 Jammer or Layer-2 Beacon Flood mitigation; hardware MAC filter; 5GHz backhaul failover.
    FloodJamSurvival = 0x04,
    /// Synchronizes WROOM, C5, and S3 Sense onto one target MAC/fingerprint for 3-point RSSI radar.
    TriangulateLock = 0x05,
    /// Shrinks S3 PCAP ring to 4MB, powers on OV2640 Camera + PDM Mic for physical intruder correlation.
    SentinelCorrelate = 0x06,
    /// Pillar 1 (DETECT): Active WIDS rule enforcement & BLE spam filtering across all nodes.
    IdsEnforce = 0x07,
    /// Pillar 2 (DECEIVE): Activates WROOM FakeSoftAp & BLE Canary GATT decoys while S3/C5 monitor trips.
    HoneypotLure = 0x08,
    /// Pillar 3/4 (DEFEND & PROVE): Freezes DMA PCAP rings, seals SHA-256 evidence chain, arms Cam/Mic.
    ForensicLockdown = 0x09,
    /// Pillar 3/4 (SURVIVE): Out-of-band LoRa SX1262 12-byte FeatureVector store-and-forward mode.
    MeshSurvive = 0x0A,
}

impl PolicyMode {
    pub const fn from_u8(v: u8) -> Option<Self> {
        match v {
            0x01 => Some(Self::WideRecon),
            0x02 => Some(Self::AnomalyTriage),
            0x03 => Some(Self::SurgicalCapture),
            0x04 => Some(Self::FloodJamSurvival),
            0x05 => Some(Self::TriangulateLock),
            0x06 => Some(Self::SentinelCorrelate),
            0x07 => Some(Self::IdsEnforce),
            0x08 => Some(Self::HoneypotLure),
            0x09 => Some(Self::ForensicLockdown),
            0x0A => Some(Self::MeshSurvive),
            _ => None,
        }
    }

    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::WideRecon => "WIDE_RECON",
            Self::AnomalyTriage => "ANOMALY_TRIAGE",
            Self::SurgicalCapture => "SURGICAL_CAPTURE",
            Self::FloodJamSurvival => "FLOOD_JAM_SURVIVAL",
            Self::TriangulateLock => "TRIANGULATE_LOCK",
            Self::SentinelCorrelate => "SENTINEL_CORRELATE",
            Self::IdsEnforce => "IDS_ENFORCE",
            Self::HoneypotLure => "HONEYPOT_LURE",
            Self::ForensicLockdown => "FORENSIC_LOCKDOWN",
            Self::MeshSurvive => "MESH_SURVIVE",
        }
    }
}

/// Operating mode specifically for the two SPI-attached nRF24L01+ radios on the ESP32-WROOM.
#[repr(u8)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum DualNrfPolicy {
    /// nRF#1 sweeps Ch 0..62 (2400-2462MHz), nRF#2 sweeps Ch 63..125 (2463-2525MHz incl. Ghost Band).
    SplitSpectrumWaterfall = 0x01,
    /// nRF#1 spots narrowband GFSK energy spikes; nRF#2 sniffs Promiscuous ESB (MouseJack / HID / Drone).
    HunterKillerEsb = 0x02,
    /// nRF#1 locks BLE Ch 37 (2402MHz), nRF#2 locks BLE Ch 38 (2426MHz), Internal ESP locks BLE Ch 39 (2480MHz).
    Simultaneous3ChBle = 0x03,
    /// Compares raw RPD carrier energy vs decoded packets to prove Layer-1 RF Jamming vs Layer-2 Deauth.
    Layer1JamTriage = 0x04,
}

impl DualNrfPolicy {
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::SplitSpectrumWaterfall => "SPLIT_SPECTRUM_WATERFALL",
            Self::HunterKillerEsb => "HUNTER_KILLER_ESB",
            Self::Simultaneous3ChBle => "SIMULTANEOUS_3CH_BLE",
            Self::Layer1JamTriage => "LAYER1_JAM_TRIAGE",
        }
    }
}

/// 126-channel Received Power Detector (RPD) bitmap from the two nRF24L01+ radios (`2400..=2525 MHz`).
/// Stored in 16 bytes (`128 bits`), where bit `ch` (`0..126`) is `1` if carrier energy > -64 dBm.
#[repr(C)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct NrfSpectrumBitmap {
    pub bits: [u8; 16],
}

impl NrfSpectrumBitmap {
    pub const fn empty() -> Self {
        Self { bits: [0u8; 16] }
    }

    #[inline]
    pub fn set_channel(&mut self, ch: u8, active: bool) {
        if ch < 126 {
            let byte_idx = (ch / 8) as usize;
            let bit_idx = ch % 8;
            if active {
                self.bits[byte_idx] |= 1 << bit_idx;
            } else {
                self.bits[byte_idx] &= !(1 << bit_idx);
            }
        }
    }

    #[inline]
    pub const fn get_channel(&self, ch: u8) -> bool {
        if ch >= 126 {
            return false;
        }
        let byte_idx = (ch / 8) as usize;
        let bit_idx = ch % 8;
        (self.bits[byte_idx] & (1 << bit_idx)) != 0
    }

    /// Counts active carrier channels in the "Ghost Band" (`2485..=2525 MHz`, nRF channels `85..=125`)
    /// which standard Wi-Fi and BLE radios cannot tune to.
    pub fn ghost_band_active_count(&self) -> u8 {
        let mut count = 0u8;
        let mut ch = 85u8;
        while ch <= 125 {
            if self.get_channel(ch) {
                count += 1;
            }
            ch += 1;
        }
        count
    }

    /// Counts active carrier energy across the 3 primary BLE advertising frequencies
    /// (`2402 MHz` = Ch 2, `2426 MHz` = Ch 26, `2480 MHz` = Ch 80).
    pub fn ble_adv_carrier_saturation(&self) -> u8 {
        let mut c = 0;
        if self.get_channel(2) {
            c += 1;
        }
        if self.get_channel(26) {
            c += 1;
        }
        if self.get_channel(80) {
            c += 1;
        }
        c
    }
}

/// Compact 24-byte telemetry frame emitted by any node in the swarm over ESP-NOW every window (250ms).
#[repr(C)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct NodeTelemetry {
    pub node_id: u8,              // NodeId
    pub active_policy: u8,        // PolicyMode
    pub sub_policy: u8,           // DualNrfPolicy or sensor sub-mode
    pub primary_channel: u8,      // Current Wi-Fi / nRF channel (1..165)
    pub cpu_load_pct: u8,         // 0..=100%
    pub free_sram_kb: u16,        // Internal SRAM remaining (critical on 384KB C5)
    pub free_psram_kb: u16,       // Octal PSRAM remaining (8192KB on S3 Sense, 0 on C5/WROOM)
    pub ringbuf_drops: u16,       // DMA / RingBuffer packet drops
    pub wifi_mgmt_fps: u16,       // 802.11 Beacon/Probe/Auth frames per sec
    pub deauth_disassoc_cnt: u16, // Layer-2 Deauth / Disassoc attack frames
    pub eapol_handshake_cnt: u8,  // WPA2/WPA3 EAPOL frames captured
    pub ble_adv_fps: u16,         // BLE Advertisements per second
    pub bt_classic_inq_cnt: u8,   // BT Classic (BR/EDR) devices found (WROOM only)
    pub ghost_band_hits: u8,      // 2485-2525 MHz non-Wi-Fi hits (WROOM nRF24 only)
    pub esb_hid_frames: u8,       // Promiscuous Enhanced ShockBurst / MouseJack frames
    pub zigbee_pan_frames: u8,    // 802.15.4 frames (ESP32-C5 only)
    pub peak_anomaly_rssi: i8,    // Strongest suspicious signal RSSI in dBm (e.g. -34)
    pub crc8: u8,                 // Integrity checksum
}

impl NodeTelemetry {
    pub const SIZE: usize = 24;

    pub fn to_bytes(&self) -> [u8; Self::SIZE] {
        let mut buf = [0u8; Self::SIZE];
        buf[0] = self.node_id;
        buf[1] = self.active_policy;
        buf[2] = self.sub_policy;
        buf[3] = self.primary_channel;
        buf[4] = self.cpu_load_pct;
        buf[5..7].copy_from_slice(&self.free_sram_kb.to_le_bytes());
        buf[7..9].copy_from_slice(&self.free_psram_kb.to_le_bytes());
        buf[9..11].copy_from_slice(&self.ringbuf_drops.to_le_bytes());
        buf[11..13].copy_from_slice(&self.wifi_mgmt_fps.to_le_bytes());
        buf[13..15].copy_from_slice(&self.deauth_disassoc_cnt.to_le_bytes());
        buf[15] = self.eapol_handshake_cnt;
        buf[16..18].copy_from_slice(&self.ble_adv_fps.to_le_bytes());
        buf[18] = self.bt_classic_inq_cnt;
        buf[19] = self.ghost_band_hits;
        buf[20] = self.esb_hid_frames;
        buf[21] = self.zigbee_pan_frames;
        buf[22] = self.peak_anomaly_rssi as u8;
        buf[23] = compute_crc8(&buf[0..23]);
        buf
    }

    pub fn from_bytes(buf: &[u8; Self::SIZE]) -> Option<Self> {
        let expected_crc = compute_crc8(&buf[0..23]);
        if buf[23] != expected_crc {
            return None;
        }
        Some(Self {
            node_id: buf[0],
            active_policy: buf[1],
            sub_policy: buf[2],
            primary_channel: buf[3],
            cpu_load_pct: buf[4],
            free_sram_kb: u16::from_le_bytes([buf[5], buf[6]]),
            free_psram_kb: u16::from_le_bytes([buf[7], buf[8]]),
            ringbuf_drops: u16::from_le_bytes([buf[9], buf[10]]),
            wifi_mgmt_fps: u16::from_le_bytes([buf[11], buf[12]]),
            deauth_disassoc_cnt: u16::from_le_bytes([buf[13], buf[14]]),
            eapol_handshake_cnt: buf[15],
            ble_adv_fps: u16::from_le_bytes([buf[16], buf[17]]),
            bt_classic_inq_cnt: buf[18],
            ghost_band_hits: buf[19],
            esb_hid_frames: buf[20],
            zigbee_pan_frames: buf[21],
            peak_anomaly_rssi: buf[22] as i8,
            crc8: buf[23],
        })
    }
}

/// Passive BLE Structural Fingerprint used to track devices across random MAC rotations.
#[repr(C)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct BleDeviceFingerprint {
    /// Current (possibly randomized) 48-bit BLE MAC address.
    pub current_mac: [u8; 6],
    /// Structural hash invariant across MAC rotations (computed over AD Type order,
    /// Manufacturer ID e.g. 0x004C Apple Continuity / 0x0006 MS SwiftPair, TX power, PDU length).
    pub structural_hash: u32,
    /// Observed advertising interval in 0.625ms units.
    pub adv_interval_units: u16,
    /// Company ID from Manufacturer Specific Data (`0xFF` AD type), e.g., `0x004C` = Apple.
    pub company_id: u16,
    /// RSSI measured at each of the 3 swarm anchors (`[WROOM, C5, S3_Sense]`) for triangulation.
    pub anchor_rssi: [i8; 3],
    /// Flag indicating suspected BLE spammer (Flipper Zero / SourApple / FastPair flood).
    pub is_ble_spam: bool,
}

/// Command packet (12 bytes) broadcast from the Raspberry Pi 5 Ferrum Brain to the ESP Swarm.
#[repr(C)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct FerrumPolicyCmd {
    pub target_node: u8,             // NodeId (or 0xFF Broadcast)
    pub policy_mode: u8,             // PolicyMode
    pub dual_nrf_mode: u8,           // DualNrfPolicy for WROOM's 2x nRF24 modules
    pub pinned_channels: [u8; 4],    // Up to 4 Wi-Fi/nRF channels to lock onto
    pub dwell_time_ms: u16,          // Channel hop dwell time in milliseconds
    pub cpu_freq_mhz: u8,            // 80, 160, or 240 MHz
    pub s3_psram_pcap_quota_kb: u16, // Dynamic allocation of S3's 8MB PSRAM to PCAP vs Cam/GATT
    pub crc8: u8,
}

impl FerrumPolicyCmd {
    pub const SIZE: usize = 13;

    pub fn to_bytes(&self) -> [u8; Self::SIZE] {
        let mut buf = [0u8; Self::SIZE];
        buf[0] = self.target_node;
        buf[1] = self.policy_mode;
        buf[2] = self.dual_nrf_mode;
        buf[3..7].copy_from_slice(&self.pinned_channels);
        buf[7..9].copy_from_slice(&self.dwell_time_ms.to_le_bytes());
        buf[9] = self.cpu_freq_mhz;
        buf[10..12].copy_from_slice(&self.s3_psram_pcap_quota_kb.to_le_bytes());
        buf[12] = compute_crc8(&buf[0..12]);
        buf
    }

    pub fn from_bytes(buf: &[u8; Self::SIZE]) -> Option<Self> {
        if buf[12] != compute_crc8(&buf[0..12]) {
            return None;
        }
        Some(Self {
            target_node: buf[0],
            policy_mode: buf[1],
            dual_nrf_mode: buf[2],
            pinned_channels: [buf[3], buf[4], buf[5], buf[6]],
            dwell_time_ms: u16::from_le_bytes([buf[7], buf[8]]),
            cpu_freq_mhz: buf[9],
            s3_psram_pcap_quota_kb: u16::from_le_bytes([buf[10], buf[11]]),
            crc8: buf[12],
        })
    }
}

/// Fast tableless CRC-8 (`poly = 0x07`) suitable for `no_std` RISC-V and Xtensa ISRs.
pub const fn compute_crc8(data: &[u8]) -> u8 {
    let mut crc = 0x00u8;
    let mut i = 0;
    while i < data.len() {
        crc ^= data[i];
        let mut bit = 0;
        while bit < 8 {
            if (crc & 0x80) != 0 {
                crc = (crc << 1) ^ 0x07;
            } else {
                crc <<= 1;
            }
            bit += 1;
        }
        i += 1;
    }
    crc
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_telemetry_and_ghost_band() {
        let mut bmp = NrfSpectrumBitmap::empty();
        bmp.set_channel(2, true);
        bmp.set_channel(95, true); // 2495 MHz Ghost Band!
        bmp.set_channel(110, true); // 2510 MHz Ghost Band!
        assert_eq!(bmp.ghost_band_active_count(), 2);
        assert_eq!(bmp.ble_adv_carrier_saturation(), 1);

        let mut t = NodeTelemetry {
            node_id: NodeId::WroomDualNrf as u8,
            active_policy: PolicyMode::AnomalyTriage as u8,
            sub_policy: DualNrfPolicy::HunterKillerEsb as u8,
            primary_channel: 95,
            cpu_load_pct: 64,
            free_sram_kb: 312,
            free_psram_kb: 0,
            ringbuf_drops: 0,
            wifi_mgmt_fps: 180,
            deauth_disassoc_cnt: 0,
            eapol_handshake_cnt: 2,
            ble_adv_fps: 410,
            bt_classic_inq_cnt: 3,
            ghost_band_hits: 14,
            esb_hid_frames: 5,
            zigbee_pan_frames: 0,
            peak_anomaly_rssi: -38,
            crc8: 0,
        };
        let bytes = t.to_bytes();
        t.crc8 = bytes[23];
        let decoded = NodeTelemetry::from_bytes(&bytes).expect("CRC8 valid");
        assert_eq!(decoded, t);
    }
}

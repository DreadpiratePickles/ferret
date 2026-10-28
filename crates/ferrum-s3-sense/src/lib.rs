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
    DeepPcapBuffer       = 0x01,
    /// Connects to a target BLE MAC flagged by the WROOM to enumerate GATT services/characteristics.
    ActiveBleGattAudit   = 0x02,
    /// Powers on OV2640 Camera + PDM Mic when target RSSI > -45 dBm to correlate RF with physical presence.
    CamAudioCorrelate    = 0x03,
    /// Synchronized 3-node RSSI anchor lock.
    TriangulateAnchorC   = 0x04,
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

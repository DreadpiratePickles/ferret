//! Telemetry -> normalized signal vector.
//!
//! Every signal is an integer in `0..=100`. The thresholds of the retired `if/else` ladder in
//! `ferrum-brain` are preserved as the *activation points*: crossing one saturates the signal to
//! `100`, while readings below it ramp over a small low range (see the `*_SUB_MAX` constants) so
//! that sub-threshold noise is still visible to the model but can never out-vote the quiet-baseline
//! prior. All math is saturating/integer only.

use ferrum_proto::NodeTelemetry;

/// Number of signals in a [`SignalVector`].
pub const N_SIGNALS: usize = 6;

/// Max value of a sub-threshold (not yet activated) reading, per signal.
const JAM_SUB_MAX: u32 = 5;
const PROX_SUB_MAX: u32 = 12;
const DEAUTH_SUB_MAX: u32 = 10;
const BT_SUB_MAX: u32 = 15;

/// Legacy activation thresholds (identical to the retired ladder).
const JAM_CHANNELS: u8 = 40;
const PROXIMITY_DBM: i8 = -42;
/// Weakest RSSI that still registers a (sub-threshold) proximity reading.
const PROXIMITY_FLOOR_DBM: i16 = -70;
const DEAUTH_COUNT: u16 = 5;
const BLE_ADV_FPS: u16 = 350;

/// The six normalized inputs to the scoring model (each `0..=100`).
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct SignalVector {
    /// nRF24 RPD-pegged channel count (>40 channels => 100).
    pub jam_ratio: u8,
    /// Strongest close-range anomaly on WROOM/S3 (> -42 dBm => 100).
    pub proximity: u8,
    /// Ghost-band (2485-2525 MHz) hits or ESB/MouseJack HID frames (any => 100).
    pub ghost_esb: u8,
    /// 5 GHz deauth (>5) or any EAPOL on the C5 (=> 100).
    pub deauth_eapol: u8,
    /// BT Classic inquiry (any) or BLE adv rate (>350 fps) on WROOM (=> 100).
    pub bt_ble: u8,
    /// uConsole Sub-GHz burst present (=> 100).
    pub subghz: u8,
}

impl SignalVector {
    /// Signals in [`SignalKind`] index order.
    pub const fn as_array(&self) -> [u8; N_SIGNALS] {
        [
            self.jam_ratio,
            self.proximity,
            self.ghost_esb,
            self.deauth_eapol,
            self.bt_ble,
            self.subghz,
        ]
    }
}

/// Identifies one column of the scoring model; used to explain *why* a policy was chosen.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum SignalKind {
    JamRatio = 0,
    Proximity = 1,
    GhostEsb = 2,
    DeauthEapol = 3,
    BtBle = 4,
    Subghz = 5,
}

impl SignalKind {
    pub const ALL: [SignalKind; N_SIGNALS] = [
        SignalKind::JamRatio,
        SignalKind::Proximity,
        SignalKind::GhostEsb,
        SignalKind::DeauthEapol,
        SignalKind::BtBle,
        SignalKind::Subghz,
    ];

    pub const fn index(self) -> usize {
        self as usize
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            SignalKind::JamRatio => "jam_ratio",
            SignalKind::Proximity => "proximity",
            SignalKind::GhostEsb => "ghost_esb",
            SignalKind::DeauthEapol => "deauth_eapol",
            SignalKind::BtBle => "bt_ble",
            SignalKind::Subghz => "subghz",
        }
    }
}

/// Maps the raw swarm telemetry to a [`SignalVector`].
pub fn signals_from(
    wroom: &NodeTelemetry,
    c5: &NodeTelemetry,
    s3: &NodeTelemetry,
    rpd_jammed_channels: u8,
    subghz_burst_mhz: Option<u16>,
) -> SignalVector {
    // Jam: > 40 channels pegged.
    let jam_ratio = if rpd_jammed_channels > JAM_CHANNELS {
        100
    } else {
        (rpd_jammed_channels as u32 * JAM_SUB_MAX / JAM_CHANNELS as u32) as u8
    };

    // Proximity: strongest of WROOM / S3 anomaly RSSI, > -42 dBm saturates.
    let peak = wroom.peak_anomaly_rssi.max(s3.peak_anomaly_rssi);
    let proximity = if peak > PROXIMITY_DBM {
        100
    } else if (peak as i16) <= PROXIMITY_FLOOR_DBM {
        0
    } else {
        let span = (PROXIMITY_DBM as i16 - PROXIMITY_FLOOR_DBM) as u32; // 28 dB
        ((peak as i16 - PROXIMITY_FLOOR_DBM) as u32 * PROX_SUB_MAX / span) as u8
    };

    // Ghost band / ESB HID: any hit activates.
    let ghost_esb = if wroom.ghost_band_hits > 0 || wroom.esb_hid_frames > 0 {
        100
    } else {
        0
    };

    // Deauth / EAPOL on the 5 GHz C5.
    let deauth_eapol = if c5.deauth_disassoc_cnt > DEAUTH_COUNT || c5.eapol_handshake_cnt > 0 {
        100
    } else {
        (c5.deauth_disassoc_cnt as u32 * DEAUTH_SUB_MAX / DEAUTH_COUNT as u32) as u8
    };

    // BT Classic or elevated BLE advertising.
    let bt_ble = if wroom.bt_classic_inq_cnt > 0 || wroom.ble_adv_fps > BLE_ADV_FPS {
        100
    } else {
        (wroom.ble_adv_fps as u32 * BT_SUB_MAX / BLE_ADV_FPS as u32) as u8
    };

    let subghz = if subghz_burst_mhz.is_some() { 100 } else { 0 };

    SignalVector {
        jam_ratio,
        proximity,
        ghost_esb,
        deauth_eapol,
        bt_ble,
        subghz,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ferrum_proto::NodeTelemetry;

    fn quiet() -> NodeTelemetry {
        NodeTelemetry {
            node_id: 1,
            active_policy: 1,
            sub_policy: 1,
            primary_channel: 6,
            cpu_load_pct: 10,
            free_sram_kb: 100,
            free_psram_kb: 0,
            ringbuf_drops: 0,
            wifi_mgmt_fps: 90,
            deauth_disassoc_cnt: 0,
            eapol_handshake_cnt: 0,
            ble_adv_fps: 0,
            bt_classic_inq_cnt: 0,
            ghost_band_hits: 0,
            esb_hid_frames: 0,
            zigbee_pan_frames: 0,
            peak_anomaly_rssi: -70,
            crc8: 0,
        }
    }

    #[test]
    fn quiet_environment_has_negligible_signals() {
        let q = quiet();
        let s = signals_from(&q, &q, &q, 3, None);
        assert!(s.jam_ratio <= 5 && s.proximity == 0 && s.ghost_esb == 0);
        assert!(s.deauth_eapol <= 10 && s.bt_ble <= 15 && s.subghz == 0);
    }

    #[test]
    fn legacy_thresholds_are_the_activation_points() {
        let q = quiet();
        assert_eq!(signals_from(&q, &q, &q, 41, None).jam_ratio, 100);
        assert!(signals_from(&q, &q, &q, 40, None).jam_ratio < 20);
        let mut near = quiet();
        near.peak_anomaly_rssi = -41;
        assert_eq!(signals_from(&near, &q, &q, 0, None).proximity, 100);
        near.peak_anomaly_rssi = -42;
        assert!(signals_from(&near, &q, &q, 0, None).proximity < 20);
        assert_eq!(
            signals_from(&q, &q, &near, 0, None).proximity,
            signals_from(&near, &q, &q, 0, None).proximity
        );
        let mut g = quiet();
        g.ghost_band_hits = 1;
        assert_eq!(signals_from(&g, &q, &q, 0, None).ghost_esb, 100);
        let mut c5 = quiet();
        c5.deauth_disassoc_cnt = 6;
        assert_eq!(signals_from(&q, &c5, &q, 0, None).deauth_eapol, 100);
        c5.deauth_disassoc_cnt = 5;
        assert!(signals_from(&q, &c5, &q, 0, None).deauth_eapol < 20);
        c5.eapol_handshake_cnt = 1;
        assert_eq!(signals_from(&q, &c5, &q, 0, None).deauth_eapol, 100);
        let mut b = quiet();
        b.ble_adv_fps = 351;
        assert_eq!(signals_from(&b, &q, &q, 0, None).bt_ble, 100);
        b.ble_adv_fps = 350;
        assert!(signals_from(&b, &q, &q, 0, None).bt_ble < 20);
        b.bt_classic_inq_cnt = 1;
        assert_eq!(signals_from(&b, &q, &q, 0, None).bt_ble, 100);
        assert_eq!(signals_from(&q, &q, &q, 0, Some(433)).subghz, 100);
    }
}

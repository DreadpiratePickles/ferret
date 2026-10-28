#![no_std]

//! `ferrum-deceive` — RF deception layer: fake softAPs, BLE decoy beacons, canary GATT services.
//!
//! Pillar 2 (DECEIVE). Decoys live on the WROOM's internal radio during `HONEYPOT_LURE`.
//! No legitimate device should ever interact with them — any probe, association, connection
//! or GATT read is a zero-false-positive tripwire. `TripwireEvent` frames are relayed to the
//! Pi 5 over the authenticated `ferrum-secure` channel and consumed by `ferrum-ids`.

use ferrum_proto::compute_crc8;

/// A fake infrastructure AP advertised by the WROOM softAP peripheral. It has no backend —
/// DHCP, DNS and upstream are deliberately sink-holed so an attacker's client hangs while the
/// swarm records everything.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct FakeSoftAp {
    pub ssid: [u8; 32],
    pub ssid_len: u8,
    pub channel: u8,          // 1..=11 (2.4 GHz)
    pub bssid: [u8; 6],
    pub seq: u16,             // 802.11 sequence counter (increments per beacon)
    pub beacon_interval_tu: u16,
}

impl FakeSoftAp {
    pub fn new(ssid: &str, channel: u8, bssid: [u8; 6]) -> Self {
        let mut s = [0u8; 32];
        let bytes = ssid.as_bytes();
        let len = bytes.len().min(32);
        s[..len].copy_from_slice(&bytes[..len]);
        Self { ssid: s, ssid_len: len as u8, channel, bssid, seq: 0, beacon_interval_tu: 100 }
    }

    /// Build one management beacon frame (fixed 128-byte staging buffer, returns used length).
    /// Layout: 802.11 beacon header + fixed parameters + SSID IE + supported-rates IE.
    pub fn build_beacon_frame(&mut self) -> ([u8; 128], usize) {
        let mut f = [0u8; 128];
        f[0] = 0x80; // Frame Control: Beacon
        f[1] = 0x00;
        // Addr1 = broadcast, Addr2 = Addr3 = BSSID
        f[4..10].fill(0xFF);
        f[10..16].copy_from_slice(&self.bssid);
        f[16..22].copy_from_slice(&self.bssid);
        f[22] = (self.seq << 4) as u8;
        f[23] = (self.seq >> 4) as u8;
        self.seq = self.seq.wrapping_add(1);
        // Timestamp: 64-bit beacon clock (microseconds since decoy boot) — any monotonic value.
        let ts = (self.seq as u64).wrapping_mul(1024);
        f[24..32].copy_from_slice(&ts.to_le_bytes());
        f[32..34].copy_from_slice(&self.beacon_interval_tu.to_le_bytes());
        f[34] = 0x01; f[35] = 0x00; // Capability: ESS
        let mut i = 36;
        f[i] = 0x00; f[i + 1] = self.ssid_len; // SSID IE
        f[i + 2..i + 2 + self.ssid_len as usize].copy_from_slice(&self.ssid[..self.ssid_len as usize]);
        i += 2 + self.ssid_len as usize;
        f[i] = 0x01; f[i + 1] = 0x04; // Supported rates IE
        f[i + 2..i + 6].copy_from_slice(&[0x82, 0x84, 0x8B, 0x96]);
        i += 6;
        (f, i)
    }
}

/// BLE decoy beacon kinds.
#[repr(u8)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum DecoyKind {
    /// Apple iBeacon (company 0x004C) — lures proximity-tracking recon.
    IBeacon = 0x01,
    /// Eddystone-UID — lures IoT/shadow-IT scanners.
    EddystoneUid = 0x02,
    /// Canary GATT service advertisement (see `CanaryGattService`).
    CanaryGatt = 0x03,
}

/// A BLE decoy beacon with a per-location canary ID. The UUID/namespace doubles as a
/// canary token: if this ID is ever probed from outside the swarm's coverage envelope,
/// the token has leaked.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct BleDecoyBeacon {
    pub kind: DecoyKind,
    pub canary_id: u16,        // per-decoy, per-location unique
    pub uuid: [u8; 16],        // iBeacon UUID / Eddystone namespace+instance
    pub major: u16,
    pub minor: u16,
    pub tx_power_dbm: i8,
}

impl BleDecoyBeacon {
    /// Build the 31-byte BLE advertising payload (flags AD structure + manufacturer data).
    pub fn build_adv_payload(&self) -> ([u8; 31], usize) {
        let mut p = [0u8; 31];
        p[0] = 0x02; p[1] = 0x01; p[2] = 0x06; // Flags: BR/EDR not supported
        match self.kind {
            DecoyKind::IBeacon => {
                p[3] = 0x1A; p[4] = 0xFF; // Len 26, Manufacturer Specific
                p[5] = 0x4C; p[6] = 0x00; // Apple
                p[7] = 0x02; p[8] = 0x15; // iBeacon type/len
                p[9..25].copy_from_slice(&self.uuid);
                p[25..27].copy_from_slice(&self.major.to_be_bytes());
                p[27..29].copy_from_slice(&self.minor.to_be_bytes());
                p[29] = self.tx_power_dbm as u8;
                (p, 30)
            }
            DecoyKind::EddystoneUid => {
                p[3] = 0x17; p[4] = 0x16; // Len 23, Service Data
                p[5] = 0xAA; p[6] = 0xFE; // Eddystone UUID
                p[7] = 0x00;              // Frame type: UID
                p[8] = self.tx_power_dbm as u8;
                p[9..17].copy_from_slice(&self.uuid[..8]);  // namespace
                p[17..23].copy_from_slice(&self.uuid[8..14]); // instance
                (p, 23)
            }
            DecoyKind::CanaryGatt => {
                p[3] = 0x15; p[4] = 0x16; // Service data
                p[5] = 0xF1; p[6] = 0xFE; // 16-bit canary service UUID (custom)
                p[7..9].copy_from_slice(&self.canary_id.to_be_bytes());
                p[9..25].copy_from_slice(&self.uuid);
                (p, 25)
            }
        }
    }
}

/// Decoy GATT service name planted in the canary advertisement — bait for service scanners.
pub const CANARY_DECOY_NAME: &[u8; 21] = b"BUILDING_ACCESS_CFG\x00";

/// Tripwire event kinds (what the intruder did to the decoy).
#[repr(u8)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum TripwireKind {
    ProbeRequest           = 0x01, // Wi-Fi probe for the decoy SSID
    Association            = 0x02, // Wi-Fi association attempt
    DeauthAgainstDecoy     = 0x03, // attacker deauthing our decoy (very high value)
    BleConnect             = 0x04,
    GattRead               = 0x05,
    CanaryProbedExternally = 0x06, // canary ID seen outside swarm envelope
}

/// 24-byte tripwire event relayed to the Pi 5 (ESP-NOW / LoRa).
#[repr(C)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct TripwireEvent {
    pub decoy_id: u16,
    pub kind: u8,               // TripwireKind
    pub intruder_mac: [u8; 6],
    pub rssi_dbm: i8,
    pub timestamp_s: u32,
    pub node_id: u8,
    pub crc8: u8,
}

impl TripwireEvent {
    pub const SIZE: usize = 24;

    pub fn new(decoy_id: u16, kind: TripwireKind, mac: [u8; 6], rssi: i8, ts: u32, node: u8) -> Self {
        Self { decoy_id, kind: kind as u8, intruder_mac: mac, rssi_dbm: rssi, timestamp_s: ts, node_id: node, crc8: 0 }
    }

    pub fn to_bytes(&self) -> [u8; Self::SIZE] {
        let mut b = [0u8; Self::SIZE];
        b[0..2].copy_from_slice(&self.decoy_id.to_le_bytes());
        b[2] = self.kind;
        b[3..9].copy_from_slice(&self.intruder_mac);
        b[9] = self.rssi_dbm as u8;
        b[10..14].copy_from_slice(&self.timestamp_s.to_le_bytes());
        b[14] = self.node_id;
        b[15] = compute_crc8(&b[0..15]);
        b
    }

    pub fn from_bytes(buf: &[u8; Self::SIZE]) -> Option<Self> {
        if buf[15] != compute_crc8(&buf[0..15]) {
            return None;
        }
        let mut mac = [0u8; 6];
        mac.copy_from_slice(&buf[3..9]);
        Some(Self {
            decoy_id: u16::from_le_bytes([buf[0], buf[1]]),
            kind: buf[2],
            intruder_mac: mac,
            rssi_dbm: buf[9] as i8,
            timestamp_s: u32::from_le_bytes([buf[10], buf[11], buf[12], buf[13]]),
            node_id: buf[14],
            crc8: buf[15],
        })
    }

    pub fn kind(&self) -> Option<TripwireKind> {
        match self.kind {
            0x01 => Some(TripwireKind::ProbeRequest),
            0x02 => Some(TripwireKind::Association),
            0x03 => Some(TripwireKind::DeauthAgainstDecoy),
            0x04 => Some(TripwireKind::BleConnect),
            0x05 => Some(TripwireKind::GattRead),
            0x06 => Some(TripwireKind::CanaryProbedExternally),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn beacon_frame_is_well_formed() {
        let ssid = "Corp-Guest-IoT-Setup";
        let mut ap = FakeSoftAp::new(ssid, 6, [0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01]);
        let (f, len) = ap.build_beacon_frame();
        assert_eq!(f[0], 0x80);
        assert_eq!(&f[4..10], &[0xFF; 6]);
        assert_eq!(f[36], 0x00); // SSID IE
        assert_eq!(f[37], ssid.len() as u8);
        assert!(len > 40 && len <= 128);
        // Sequence increments per beacon.
        let (_, _) = ap.build_beacon_frame();
        assert_eq!(ap.seq, 2);
    }

    #[test]
    fn ibeacon_payload_matches_apple_layout() {
        let b = BleDecoyBeacon {
            kind: DecoyKind::IBeacon,
            canary_id: 0x0007,
            uuid: [0x11; 16],
            major: 1, minor: 2, tx_power_dbm: -59,
        };
        let (p, len) = b.build_adv_payload();
        assert_eq!(len, 30);
        assert_eq!(&p[5..7], &[0x4C, 0x00]); // Apple company ID
        assert_eq!(&p[7..9], &[0x02, 0x15]); // iBeacon
        assert_eq!(p[29], (-59i8) as u8);
    }

    #[test]
    fn tripwire_event_wire_roundtrip() {
        let e = TripwireEvent::new(
            0x0007, TripwireKind::Association,
            [0x64, 0xA2, 0x11, 0x09, 0xBC, 0x01], -41, 1_700_000_120, 0x01,
        );
        let b = e.to_bytes();
        let back = TripwireEvent::from_bytes(&b).expect("crc ok");
        assert_eq!(back.kind(), Some(TripwireKind::Association));
        assert_eq!(back.intruder_mac, e.intruder_mac);
        let mut bad = b;
        bad[9] ^= 0xFF;
        assert!(TripwireEvent::from_bytes(&bad).is_none());
    }
}

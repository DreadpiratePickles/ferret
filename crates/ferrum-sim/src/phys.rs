//! Path-loss physics and RSSI trilateration (ported from `ferrum-brain`).

/// Strongest RSSI the model will report (dBm).
pub const RSSI_MAX_DBM: i8 = -25;
/// Weakest RSSI the model will report (dBm).
pub const RSSI_MIN_DBM: i8 = -90;
/// Nearest modelled distance (m).
pub const DIST_MIN_M: f32 = 0.3;
/// Farthest modelled distance (m).
pub const DIST_MAX_M: f32 = 12.0;
/// Path-loss exponent `n`.
pub const PATH_LOSS_EXP: f32 = 2.2;
/// Anchor positions in metres: WROOM, C5, S3.
pub const ANCHORS: [(f32, f32); 3] = [(0.0, 0.0), (6.0, 0.0), (3.0, 5.2)];

/// Unclamped received power (dBm) at `dist_m`, for an emitter whose received power at the
/// 1 m reference distance is `tx_dbm` (`-40` for the reference transmitter).
/// Distances below [`DIST_MIN_M`] are floored so the result stays finite.
pub fn path_loss_dbm(tx_dbm: i8, dist_m: f32) -> f32 {
    let d = if dist_m.is_nan() {
        DIST_MAX_M
    } else {
        dist_m.max(DIST_MIN_M)
    };
    f32::from(tx_dbm) - 10.0 * PATH_LOSS_EXP * d.log10()
}

/// Log-distance path-loss: `RSSI = tx_dbm - 10 n log10(d)`, `n = 2.2`, clamped to
/// [`RSSI_MIN_DBM`]`..=`[`RSSI_MAX_DBM`].
pub fn rssi_from_distance(tx_dbm: i8, dist_m: f32) -> i8 {
    path_loss_dbm(tx_dbm, dist_m)
        .round()
        .clamp(f32::from(RSSI_MIN_DBM), f32::from(RSSI_MAX_DBM)) as i8
}

/// Inverse of the model with `tx = -40 dBm @ 1 m`: RSSI -> distance, RSSI clamped to
/// `[-90, -25]` and distance to `[0.3, 12]` m.
pub fn distance_from_rssi(rssi: i8) -> f32 {
    let clamped = f32::from(rssi).clamp(f32::from(RSSI_MIN_DBM), f32::from(RSSI_MAX_DBM));
    let exp = (-40.0 - clamped) / (10.0 * PATH_LOSS_EXP);
    10.0_f32.powf(exp).clamp(DIST_MIN_M, DIST_MAX_M)
}

/// 3-node spatial RSSI trilateration (`WROOM (0,0)`, `C5 (6,0)`, `S3 (3,5.2)`).
/// Returns `(x, y, [d_wroom, d_c5, d_s3])` as an inverse-square weighted centroid.
pub fn trilaterate(anchor_rssi: [i8; 3]) -> (f32, f32, [f32; 3]) {
    let d = anchor_rssi.map(distance_from_rssi);
    // Inverse-distance weighted centroid inside the 6 m x 5.2 m sensor triangle.
    let w = d.map(|di| 1.0 / (di * di + 0.1));
    let w_sum: f32 = w.iter().sum();
    let x = (0..3).map(|i| w[i] * ANCHORS[i].0).sum::<f32>() / w_sum;
    let y = (0..3).map(|i| w[i] * ANCHORS[i].1).sum::<f32>() / w_sum;
    (x, y, d)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rssi_decreases_with_distance() {
        let mut prev = i8::MAX;
        for d in [0.5_f32, 1.0, 2.0, 4.0, 8.0, 12.0] {
            let r = rssi_from_distance(-40, d);
            assert!(
                r <= prev,
                "rssi must not increase with distance ({d} m: {r} > {prev})"
            );
            prev = r;
        }
        assert!(rssi_from_distance(-40, 1.0) > rssi_from_distance(-40, 10.0));
    }

    #[test]
    fn test_rssi_clamped() {
        for tx in [-120_i8, -60, -40, -10, 20] {
            for d in [0.0_f32, 0.01, 0.3, 1.0, 10.0, 100.0, 1.0e6] {
                let r = rssi_from_distance(tx, d);
                assert!(
                    (RSSI_MIN_DBM..=RSSI_MAX_DBM).contains(&r),
                    "tx {tx} d {d} -> {r} out of range"
                );
            }
        }
        assert_eq!(rssi_from_distance(-40, 1.0), -40);
    }

    #[test]
    fn test_trilaterate_centroid() {
        // Strongest RSSI at WROOM: the estimate sits at WROOM's corner of the triangle.
        let (x, y, d) = trilaterate([-45, -80, -80]);
        assert!(x < 1.5 && y < 1.5, "expected near WROOM, got ({x}, {y})");
        assert!(d[0] < d[1] && d[0] < d[2]);
        // Strongest at C5: x pulled toward 6 m, y near 0.
        let (x, y, _) = trilaterate([-80, -45, -80]);
        assert!(x > 4.5 && y < 1.5, "expected near C5, got ({x}, {y})");
        // Strongest at S3: y pulled toward 5.2 m.
        let (x, y, _) = trilaterate([-80, -80, -45]);
        assert!(
            (x - 3.0).abs() < 1.5 && y > 3.5,
            "expected near S3, got ({x}, {y})"
        );
        // Equal (and saturated) readings: the geometric centroid.
        let (x, y, d) = trilaterate([-68, -71, -65]);
        assert!((x - 3.0).abs() < 0.01 && (y - 1.7333).abs() < 0.01);
        assert_eq!(d, [12.0, 12.0, 12.0]);
    }

    #[test]
    fn test_trilaterate_matches_brain_narrative() {
        // Values printed by `ferrum-brain` for its scripted ticks 2 and 3.
        let (x, y, d) = trilaterate([-44, -61, -56]);
        assert!(
            (x - 0.39).abs() < 0.01 && (y - 0.39).abs() < 0.01,
            "({x}, {y})"
        );
        assert!(
            (d[0] - 1.5).abs() < 0.05 && (d[1] - 9.0).abs() < 0.05 && (d[2] - 5.3).abs() < 0.05
        );
        let (x, y, d) = trilaterate([-64, -39, -58]);
        assert!(
            (x - 5.90).abs() < 0.01 && (y - 0.11).abs() < 0.01,
            "({x}, {y})"
        );
        assert!(
            (d[0] - 12.0).abs() < 0.05 && (d[1] - 0.9).abs() < 0.05 && (d[2] - 6.6).abs() < 0.05
        );
    }
}

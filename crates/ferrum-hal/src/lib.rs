#![no_std]

//! `ferrum-hal` — hardware-abstraction traits for the Ferret swarm nodes.
//!
//! Node agents are generic over these traits so the same logic runs against
//! real `esp-hal` drivers (Phase 2) and against the mock PHYs / simulator.
//! Pure `#![no_std]`, no allocation, depends only on `ferrum-proto`.

use ferrum_proto::NodeTelemetry;

#[cfg(any(test, feature = "mock"))]
pub mod mock;

/// A radio front-end that can be tuned to a channel and probed for energy.
pub trait SpectrumScanner {
    /// Tune the radio to `ch`.
    fn set_channel(&mut self, ch: u8);
    /// Received Power Detector: `true` if carrier energy was seen on the current channel.
    fn read_rpd(&mut self) -> bool;
    /// Sample the RSSI (dBm) on the current channel.
    fn sample_rssi(&mut self) -> i8;
}

/// A passive frame source (promiscuous Wi-Fi, BLE, nRF ESB, ...).
pub trait PacketSniffer {
    /// Platform-specific captured frame representation.
    type Frame;
    /// Next captured frame, or `None` if nothing is pending.
    fn next_frame(&mut self) -> Option<Self::Frame>;
}

/// A datagram transport to the swarm (e.g. ESP-NOW).
pub trait Transport {
    type Error;
    /// Send one datagram.
    fn send(&mut self, buf: &[u8]) -> Result<(), Self::Error>;
    /// Receive one datagram into `buf`, returning its length (0 if none pending).
    fn recv(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error>;
}

/// Monotonic millisecond clock.
pub trait Clock {
    fn now_ms(&self) -> u64;
}

/// Result of an agent `tick()`: telemetry when the node is up, `Offline` when
/// its transport/radio has failed.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum NodeStatus {
    Online(NodeTelemetry),
    Offline,
}

//! Heapless mock PHYs for host tests and the simulator.
//!
//! No allocation: scripted data lives in fixed-size arrays with cursors.

pub use crate::FrameKind;
use crate::{Clock, FrameMeta, PacketSniffer, SpectrumScanner, Transport};
use ferrum_proto::ESP_NOW_MAX_PAYLOAD;

/// Number of addressable channels (`u8` channel index).
const CHANNELS: usize = 256;

/// Scripted spectrum scanner: returns a fixed `(rpd, rssi)` per channel.
/// Unscripted channels read as quiet: `(false, QUIET_RSSI)`.
#[derive(Clone, Debug)]
pub struct MockScanner {
    table: [(bool, i8); CHANNELS],
    channel: u8,
}

impl MockScanner {
    pub const QUIET_RSSI: i8 = -100;

    pub const fn new() -> Self {
        Self {
            table: [(false, Self::QUIET_RSSI); CHANNELS],
            channel: 0,
        }
    }

    /// Script the reading for channel `ch` (builder style).
    pub fn with(mut self, ch: u8, rpd: bool, rssi: i8) -> Self {
        self.table[ch as usize] = (rpd, rssi);
        self
    }

    /// Currently tuned channel.
    pub fn channel(&self) -> u8 {
        self.channel
    }
}

impl Default for MockScanner {
    fn default() -> Self {
        Self::new()
    }
}

impl SpectrumScanner for MockScanner {
    fn set_channel(&mut self, ch: u8) {
        self.channel = ch;
    }
    fn read_rpd(&mut self) -> bool {
        self.table[self.channel as usize].0
    }
    fn sample_rssi(&mut self) -> i8 {
        self.table[self.channel as usize].1
    }
}

/// Minimal captured frame: where it was heard and what it was.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct MockFrame {
    pub channel: u8,
    pub kind: FrameKind,
}

impl FrameMeta for MockFrame {
    fn kind(&self) -> FrameKind {
        self.kind
    }
    fn channel(&self) -> u8 {
        self.channel
    }
}

/// Scripted sniffer yielding up to `N` frames in order, then `None`.
#[derive(Clone, Debug)]
pub struct MockSniffer<const N: usize> {
    frames: [MockFrame; N],
    len: usize,
    cursor: usize,
}

impl<const N: usize> MockSniffer<N> {
    /// Sniffer that yields every frame in `frames`.
    pub const fn new(frames: [MockFrame; N]) -> Self {
        Self {
            frames,
            len: N,
            cursor: 0,
        }
    }

    /// Frames not yet consumed.
    pub fn remaining(&self) -> usize {
        self.len - self.cursor
    }
}

impl<const N: usize> PacketSniffer for MockSniffer<N> {
    type Frame = MockFrame;
    fn next_frame(&mut self) -> Option<MockFrame> {
        if self.cursor < self.len {
            let f = self.frames[self.cursor];
            self.cursor += 1;
            Some(f)
        } else {
            None
        }
    }
}

/// Error returned by [`MockTransport`] when `fail` is set (or on oversize send).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct TransportError;

/// Mock datagram transport. Set `fail = true` to simulate an offline node.
/// Records the last datagram sent for assertions.
#[derive(Clone, Debug)]
pub struct MockTransport {
    pub fail: bool,
    pub sent_count: u32,
    pub last_sent: [u8; ESP_NOW_MAX_PAYLOAD],
    pub last_len: usize,
}

impl MockTransport {
    pub const fn new() -> Self {
        Self {
            fail: false,
            sent_count: 0,
            last_sent: [0; ESP_NOW_MAX_PAYLOAD],
            last_len: 0,
        }
    }

    /// Transport whose `send`/`recv` always fail.
    pub const fn failing() -> Self {
        let mut t = Self::new();
        t.fail = true;
        t
    }

    /// The last successfully sent datagram.
    pub fn last_sent(&self) -> &[u8] {
        &self.last_sent[..self.last_len]
    }
}

impl Default for MockTransport {
    fn default() -> Self {
        Self::new()
    }
}

impl Transport for MockTransport {
    type Error = TransportError;

    fn send(&mut self, buf: &[u8]) -> Result<(), TransportError> {
        if self.fail || buf.len() > ESP_NOW_MAX_PAYLOAD {
            return Err(TransportError);
        }
        self.last_sent[..buf.len()].copy_from_slice(buf);
        self.last_len = buf.len();
        self.sent_count += 1;
        Ok(())
    }

    fn recv(&mut self, _buf: &mut [u8]) -> Result<usize, TransportError> {
        if self.fail {
            Err(TransportError)
        } else {
            Ok(0) // nothing pending
        }
    }
}

/// Settable clock.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct MockClock {
    pub ms: u64,
}

impl MockClock {
    pub const fn new(ms: u64) -> Self {
        Self { ms }
    }
    pub fn advance(&mut self, delta_ms: u64) {
        self.ms += delta_ms;
    }
}

impl Clock for MockClock {
    fn now_ms(&self) -> u64 {
        self.ms
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mock_transport_can_fail() {
        let mut ok = MockTransport::default();
        assert!(ok.send(&[1, 2, 3]).is_ok());
        assert_eq!(ok.last_sent(), &[1, 2, 3]);
        assert_eq!(ok.sent_count, 1);
        assert_eq!(ok.recv(&mut [0u8; 8]), Ok(0));

        let mut bad = MockTransport {
            fail: true,
            ..MockTransport::default()
        };
        assert!(bad.send(&[1, 2, 3]).is_err());
        assert!(bad.recv(&mut [0u8; 8]).is_err());
        assert_eq!(bad.sent_count, 0);
        assert!(MockTransport::failing().send(&[0]).is_err());
    }

    #[test]
    fn test_mock_scanner_scripted_per_channel() {
        let mut s = MockScanner::new().with(110, true, -34).with(6, false, -70);
        s.set_channel(110);
        assert!(s.read_rpd());
        assert_eq!(s.sample_rssi(), -34);
        s.set_channel(6);
        assert!(!s.read_rpd());
        assert_eq!(s.sample_rssi(), -70);
        s.set_channel(1);
        assert!(!s.read_rpd());
        assert_eq!(s.sample_rssi(), MockScanner::QUIET_RSSI);
    }

    #[test]
    fn test_mock_sniffer_yields_in_order_then_none() {
        let a = MockFrame {
            channel: 95,
            kind: FrameKind::Esb,
        };
        let b = MockFrame {
            channel: 6,
            kind: FrameKind::Deauth,
        };
        let mut s = MockSniffer::new([a, b]);
        assert_eq!(s.remaining(), 2);
        assert_eq!(s.next_frame(), Some(a));
        assert_eq!(s.next_frame(), Some(b));
        assert_eq!(s.next_frame(), None);
        assert_eq!(s.remaining(), 0);
    }

    #[test]
    fn test_mock_clock() {
        let mut c = MockClock::new(10);
        assert_eq!(c.now_ms(), 10);
        c.advance(250);
        assert_eq!(c.now_ms(), 260);
    }

    #[test]
    fn test_node_status_eq() {
        use crate::NodeStatus;
        assert_eq!(NodeStatus::Offline, NodeStatus::Offline);
    }
}

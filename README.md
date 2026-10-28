# Ferret (`Ferrum CyberSwarm`)

An **AI-Adaptive Rust Unikernel & Embedded Wireless Surveillance Swarm** built across **4 Operational Pillars (`DETECT`, `DECEIVE`, `DEFEND`, `PROVE`)**:
- **Control Plane:** Raspberry Pi 5 (8GB) running the **Ferrum + Laya System-1 / System-2 Decision Engine**
- **Operator Deck:** ClockworkPi **uConsole (with HackerGadgets AIOv2)** (`RTL-SDR` Sub-GHz + `LoRa SX1262`)
- **Node 1 (`0x01`):** **ESP32-WROOM + Dual nRF24L01+ Shield** (`VSPI` + `HSPI`, BT Classic `BR/EDR`, BLE 4.2, 126-Ch `2400–2525 MHz` Ghost-Band & ESB/MouseJack Sniffer + Decoy SoftAP/BLE Honeypot)
- **Node 2 (`0x02`):** **ESP32-C5 (4MB Flash, RISC-V)** (Dual-Band **5 GHz Wi-Fi 6** `Ch 36–165` + `802.15.4` Zigbee/Thread)
- **Node 3 (`0x03`):** **Seeed XIAO ESP32-S3 Sense (8MB PSRAM)** (2.4 GHz Deep PCAP Ring Buffer + Active BLE GATT Auditor + `OV2640` Camera & `PDM` Mic Sensor Fusion + Forensic Hash-Chain Sealer)

---

## Complete 10-Crate Workspace Architecture

| Crate | Target | Pillar / Role |
| :--- | :--- | :--- |
| [`crates/ferrum-proto`](./crates/ferrum-proto/src/lib.rs) | `#![no_std]` | 24B `NodeTelemetry` & 13B `FerrumPolicyCmd` wire protocol, CRC-8, 126-channel nRF24 `RPD` bitmap, 10 `PolicyMode` states (`0x01..=0x0A`) |
| [`crates/ferrum-wroom-nrf`](./crates/ferrum-wroom-nrf/src/lib.rs) | `#![no_std]` (`xtensa-esp32-none-elf`) | Dual-nRF24L01+ SPI register driver (`VSPI` + `HSPI`), Promiscuous ESB (`0xAA55` preamble), Ghost-Band (`2485–2525 MHz`) hunter-killer, and FNV-1a BLE MAC-Randomization De-Anonymizer |
| [`crates/ferrum-c5-scout`](./crates/ferrum-c5-scout/src/lib.rs) | `#![no_std]` (`riscv32imac-unknown-none-elf`) | 5 GHz UNII-1/2/3 channel scheduler, 384 KB SRAM budget guard, and 5 GHz failover survival mode |
| [`crates/ferrum-s3-sense`](./crates/ferrum-s3-sense/src/lib.rs) | `#![no_std]` (`xtensa-esp32s3-none-elf`) | Dynamic 8 MB Octal PSRAM partition controller (`PCAP Ring` vs `BLE GATT Cache` vs `OV2640 Camera + PDM Mic FFT`) |
| [`crates/ferrum-ids`](./crates/ferrum-ids/src/lib.rs) | `std` (Pi 5) | **Pillar 1 (`DETECT`):** 9-rule WIDS engine with MITRE ATT&CK tags, severity ladder, and System-2 policy escalation |
| [`crates/ferrum-deceive`](./crates/ferrum-deceive/src/lib.rs) | `#![no_std]` | **Pillar 2 (`DECEIVE`):** Sink-holed `FakeSoftAp` 802.11 beacon builder, Apple iBeacon / Eddystone-UID / Canary GATT decoys, and 24B `TripwireEvent` |
| [`crates/ferrum-secure`](./crates/ferrum-secure/src/lib.rs) | `#![no_std]` | **Pillar 3 (`DEFEND`):** FIPS 180-4 SHA-256, RFC 2104 HMAC-SHA256, anti-replay `SecureChannel`, and LoRa epoch key rotation |
| [`crates/ferrum-forensics`](./crates/ferrum-forensics/src/lib.rs) | `#![no_std]` | **Pillar 4 (`PROVE`):** SHA-256 hash-chained evidence sealing (`HashChain`, `verify_chain`) and bounded `StoreForwardQueue` |
| [`crates/ferrum-triage`](./crates/ferrum-triage/src/lib.rs) | `#![no_std]` | **Pillar 3/4 (`SURVIVE`):** 16-bin `RssiHistogram`, sliding `RateWindow`, Shannon channel entropy, and 12-byte compressed `FeatureVector` for LoRa `SX1262` |
| [`crates/ferrum-brain`](./crates/ferrum-brain/src/main.rs) | `std` (Pi 5) | End-to-end Laya System-1 + System-2 control plane, 3-node RSSI trilateration radar, and Phase-1 / Phase-2 simulation runner |

---

## Quick Start

```bash
cd ~/Downloads/ferret
cargo test --workspace
cargo run -p ferrum-brain
```

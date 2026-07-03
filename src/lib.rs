//! ALE (Adaptation Layer Entity) framing for EuroRadio communication.
//!
//! Implements ALEPKT framing as specified in UNISIG Subset-098 v3.0.0 §6.4.5
//! and Subset-037 v3.2.0 §8.3.2. Provides streaming encode/decode of ALE
//! packets over TCP for the ERTMS/ETCS signalling stack.
//!
//! Supports Class D operation over a **single TCP connection** (restricted
//! profile — the full Subset-098 Class D specifies dual redundant TCP links
//! with duplicate T-Sequence suppression, which is not yet implemented).
//! Includes CRC-CCITT checksum validation, connection handshake (AU1/AU2),
//! data transfer (DT), and disconnect indication (DI).
//!
//! # ALEPKT wire format (10-byte header + variable user data):
//! ```text
//! | Packet Length | Version | App Type | T-Seq Num | N/R Flag | Pkt Type | Checksum | User Data |
//! | 2 octets BE   | 1 octet | 1 octet  | 2 oct BE  | 1 octet  | 1 octet  | 2 octets | variable  |
//! ```
//!
//! # Usage
//! ```rust
//! use ale_frame::{AleFrameWriter, AleFrameReader, ALE_PKT_DT};
//!
//! // Write an ALEPKT DT frame
//! let mut writer = AleFrameWriter::new(0x00);
//! let mut buf = Vec::new();
//! writer.write_alepkt(&mut buf, ALE_PKT_DT, b"hello").unwrap();
//!
//! // Read it back
//! let mut reader = AleFrameReader::new();
//! let frames = reader.feed(&buf).unwrap();
//! assert_eq!(frames[0].user_data, b"hello");
//! ```

use std::fmt;
use std::io::{self, Write};

// =========================================================================================
//                                     CONSTANTS
// =========================================================================================

/// Fixed ALEPKT header size in octets.
pub const ALE_HEADER_SIZE: usize = 10;

/// Number of bytes covered by the checksum:
/// PacketLength(2) + Version(1) + AppType(1) + TSeq(2) + NR(1) + PktType(1) = 8 bytes.
const ALE_CHECKSUM_COVERED_SIZE: usize = 8;

/// Default ALE protocol version.
pub const ALE_VERSION: u8 = 1;

/// N/R flag value for the normal link (this crate's single-link profile uses 1).
pub const ALE_NR_FLAG_NORMAL: u8 = 1;

/// Maximum ALEPKT user data size (Subset-098 §6.5.3.1.3).
pub const ALE_MAX_USER_DATA: usize = 65_000;

// Packet types (Subset-098 §6.4.5.1.5 / §6.5)
/// AU1 — Connection Request (CR).
pub const ALE_PKT_AU1: u8 = 1;
/// AU2 — Connection Confirm (CC).
pub const ALE_PKT_AU2: u8 = 2;
/// DT  — Data Transfer.
pub const ALE_PKT_DT: u8 = 3;
/// DI  — Disconnect Indication.
pub const ALE_PKT_DI: u8 = 4;

/// Class D single-link coded value (Subset-037 §8.3.2 / AU1 Class of Service
/// field = 0x01 for single-link Class D). Note: full Subset-098 §6.6.2.1.6
/// specifies 0x03 for dual-link Class D.
pub const ALE_CLASS_D: u8 = 0x01;

// =========================================================================================
//                                     ERROR TYPE
// =========================================================================================

#[derive(Debug)]
pub enum AleError {
    ChecksumMismatch {
        expected: u16,
        got: u16,
    },
    InvalidPacketType(u8),
    /// Packet length field is too small (must be >= 8).
    InvalidPacketLength(u16),
    PayloadTooLarge(usize),
    Io(io::Error),
}

impl fmt::Display for AleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ChecksumMismatch { expected, got } => {
                write!(
                    f,
                    "ALEPKT checksum mismatch: expected 0x{:04X}, got 0x{:04X}",
                    expected, got
                )
            }
            Self::InvalidPacketType(t) => write!(f, "invalid ALEPKT packet type: {}", t),
            Self::InvalidPacketLength(n) => {
                write!(f, "ALEPKT packet_length too small: {} (minimum 8)", n)
            }
            Self::PayloadTooLarge(n) => write!(f, "ALEPKT payload too large: {} bytes", n),
            Self::Io(e) => write!(f, "ALE I/O error: {}", e),
        }
    }
}

impl std::error::Error for AleError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<io::Error> for AleError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

// =========================================================================================
//                                     CRC-CCITT
// =========================================================================================

/// Compute CRC-CCITT per Subset-098 §6.4.5 / ISO 3309.
///
/// - Polynomial: x^16 + x^12 + x^5 + 1 (0x1021)
/// - Initial value: 0xFFFF
/// - No final inversion (spec: "The inversion of the CRC final result shall not be performed")
#[must_use]
pub fn crc_ccitt(data: &[u8]) -> u16 {
    let mut crc: u16 = 0xFFFF;
    for &byte in data {
        crc ^= (byte as u16) << 8;
        for _ in 0..8 {
            if crc & 0x8000 != 0 {
                crc = (crc << 1) ^ 0x1021;
            } else {
                crc <<= 1;
            }
        }
    }
    crc
}

// =========================================================================================
//                                   ALEPKT HEADER
// =========================================================================================

/// Parsed ALEPKT header.
#[derive(Debug, Clone)]
pub struct AleHeader {
    /// Length of everything after this 2-byte field (header bytes + user data).
    pub packet_length: u16,
    pub version: u8,
    pub app_type: u8,
    /// Transport Sequence Number (Class D: increments per ALEPKT, wraps 65535→0).
    pub t_sequence: u16,
    /// Normal/Redundant flag (1=Normal for Class D).
    pub nr_flag: u8,
    pub packet_type: u8,
    /// CRC-CCITT checksum over the preceding 8 bytes (PacketLength through PktType).
    pub checksum: u16,
}

impl AleHeader {
    /// Serialize the header to its 10-byte wire representation (big-endian).
    pub fn encode(&self) -> [u8; ALE_HEADER_SIZE] {
        let mut buf = [0u8; ALE_HEADER_SIZE];
        buf[0..2].copy_from_slice(&self.packet_length.to_be_bytes());
        buf[2] = self.version;
        buf[3] = self.app_type;
        buf[4..6].copy_from_slice(&self.t_sequence.to_be_bytes());
        buf[6] = self.nr_flag;
        buf[7] = self.packet_type;
        buf[8..10].copy_from_slice(&self.checksum.to_be_bytes());
        buf
    }

    /// Decode a 10-byte buffer into an AleHeader, validating the CRC checksum.
    pub fn decode(buf: &[u8; ALE_HEADER_SIZE]) -> Result<Self, AleError> {
        let packet_length = u16::from_be_bytes([buf[0], buf[1]]);
        let version = buf[2];
        let app_type = buf[3];
        let t_sequence = u16::from_be_bytes([buf[4], buf[5]]);
        let nr_flag = buf[6];
        let packet_type = buf[7];
        let checksum = u16::from_be_bytes([buf[8], buf[9]]);

        // Checksum covers bytes 0..8: the 6 fields preceding the checksum (Subset-098 Table 6):
        // PacketLength(2) + Version(1) + AppType(1) + TSeqNum(2) + NR_Flag(1) + PktType(1) = 8 bytes
        let computed = crc_ccitt(&buf[0..8]);

        if computed != checksum {
            return Err(AleError::ChecksumMismatch {
                expected: computed,
                got: checksum,
            });
        }

        // Validate packet type
        match packet_type {
            ALE_PKT_AU1 | ALE_PKT_AU2 | ALE_PKT_DT | ALE_PKT_DI => {}
            _ => return Err(AleError::InvalidPacketType(packet_type)),
        }

        Ok(Self {
            packet_length,
            version,
            app_type,
            t_sequence,
            nr_flag,
            packet_type,
            checksum,
        })
    }

    /// Build a header with the correct checksum.
    ///
    /// Errors with [`AleError::PayloadTooLarge`] if `user_data_len` exceeds
    /// [`ALE_MAX_USER_DATA`]: the 16-bit Packet Length field (Subset-098
    /// §6.5.3.1.3) would otherwise silently truncate, so the length is validated
    /// with a checked conversion rather than an unchecked `as u16` cast (DP-14).
    pub fn build(
        version: u8,
        app_type: u8,
        t_sequence: u16,
        nr_flag: u8,
        packet_type: u8,
        user_data_len: usize,
    ) -> Result<Self, AleError> {
        if user_data_len > ALE_MAX_USER_DATA {
            return Err(AleError::PayloadTooLarge(user_data_len));
        }
        // packet_length = header bytes after Packet Length field (8) + user data.
        // The check above guarantees this fits in `u16`; the `try_from` keeps the
        // conversion checked (no silent narrowing) rather than trusting it.
        let packet_length = u16::try_from(ALE_CHECKSUM_COVERED_SIZE + user_data_len)
            .map_err(|_| AleError::PayloadTooLarge(user_data_len))?;

        // Build the 8 bytes that the checksum covers (PacketLength through PktType)
        let mut cksum_input = [0u8; 8];
        cksum_input[0..2].copy_from_slice(&packet_length.to_be_bytes());
        cksum_input[2] = version;
        cksum_input[3] = app_type;
        cksum_input[4..6].copy_from_slice(&t_sequence.to_be_bytes());
        cksum_input[6] = nr_flag;
        cksum_input[7] = packet_type;

        let checksum = crc_ccitt(&cksum_input);

        Ok(Self {
            packet_length,
            version,
            app_type,
            t_sequence,
            nr_flag,
            packet_type,
            checksum,
        })
    }
}

// =========================================================================================
//                                   FRAME WRITER
// =========================================================================================

/// Stateful ALEPKT writer that maintains the T-Sequence counter for Class D.
pub struct AleFrameWriter {
    t_sequence: u16,
    app_type: u8,
    version: u8,
}

impl AleFrameWriter {
    pub fn new(app_type: u8) -> Self {
        Self {
            t_sequence: 0,
            app_type,
            version: ALE_VERSION,
        }
    }

    /// Write a complete ALEPKT (header + user data) into the writer.
    ///
    /// For packet types AU1/AU2, t_sequence is always 0 (per Subset-098 §6.5.2.6.4).
    /// For DT packets, t_sequence increments after each send and wraps at 65535→0.
    pub fn write_alepkt<W: Write>(
        &mut self,
        writer: &mut W,
        packet_type: u8,
        user_data: &[u8],
    ) -> Result<(), AleError> {
        let seq = match packet_type {
            ALE_PKT_AU1 | ALE_PKT_AU2 => 0,
            _ => self.t_sequence,
        };

        // `build` validates the payload length (single source of truth) and
        // returns `PayloadTooLarge` before any bytes are written or the sequence
        // counter advances.
        let header = AleHeader::build(
            self.version,
            self.app_type,
            seq,
            ALE_NR_FLAG_NORMAL,
            packet_type,
            user_data.len(),
        )?;

        let encoded = header.encode();
        let mut frame = Vec::with_capacity(ALE_HEADER_SIZE + user_data.len());
        frame.extend_from_slice(&encoded);
        frame.extend_from_slice(user_data);
        writer.write_all(&frame).map_err(AleError::Io)?;

        // Increment t_sequence for every ALEPKT sent (Subset-098 §6.5.3.3.2.1:
        // "Incremented by 1 for each subsequent ALEPKT sent").
        // AU1/AU2 always *carry* value 0 (§6.5.2.6.4) but still advance the
        // counter so that the first DT after handshake has T-Seq=1.
        self.t_sequence = self.t_sequence.wrapping_add(1);

        Ok(())
    }

    /// Current T-Sequence number (for diagnostics).
    pub fn t_sequence(&self) -> u16 {
        self.t_sequence
    }
}

// =========================================================================================
//                                   FRAME READER
// =========================================================================================

/// Completed ALEPKT frame (header + user data).
#[derive(Debug, Clone)]
pub struct AleFrame {
    pub header: AleHeader,
    pub user_data: Vec<u8>,
}

/// Internal state machine for reassembling ALEPKTs from a TCP byte stream.
enum AleReadState {
    /// Accumulating the 10-byte header.
    ReadingHeader,
    /// Header complete, accumulating user data payload.
    ReadingPayload { header: AleHeader },
}

/// Streaming ALEPKT reader that reassembles frames from TCP byte chunks.
///
/// TCP provides a byte stream with no message boundaries. The AleFrameReader
/// handles arbitrary chunking (partial headers, partial payloads, multiple
/// frames in a single chunk).
pub struct AleFrameReader {
    state: AleReadState,
    header_buf: [u8; ALE_HEADER_SIZE],
    header_pos: usize,
    payload_buf: Vec<u8>,
    payload_pos: usize,
    expected_payload_len: usize,
}

impl Default for AleFrameReader {
    fn default() -> Self {
        Self::new()
    }
}

impl AleFrameReader {
    pub fn new() -> Self {
        Self {
            state: AleReadState::ReadingHeader,
            header_buf: [0u8; ALE_HEADER_SIZE],
            header_pos: 0,
            payload_buf: Vec::new(),
            payload_pos: 0,
            expected_payload_len: 0,
        }
    }

    /// Feed raw bytes from the TCP stream and return any completed ALE frames.
    ///
    /// Returns `Ok(frames)` for successfully parsed frames, or `Err` if a
    /// checksum mismatch or invalid packet is detected (caller should disconnect).
    pub fn feed(&mut self, data: &[u8]) -> Result<Vec<AleFrame>, AleError> {
        let mut frames = Vec::new();
        let mut pos = 0;

        while pos < data.len() {
            match &self.state {
                AleReadState::ReadingHeader => {
                    let need = ALE_HEADER_SIZE - self.header_pos;
                    let avail = data.len() - pos;
                    let copy = need.min(avail);
                    self.header_buf[self.header_pos..self.header_pos + copy]
                        .copy_from_slice(&data[pos..pos + copy]);
                    self.header_pos += copy;
                    pos += copy;

                    if self.header_pos == ALE_HEADER_SIZE {
                        let header = AleHeader::decode(&self.header_buf)?;
                        // Reject malformed packet_length that would underflow the subtraction
                        if (header.packet_length as usize) < ALE_CHECKSUM_COVERED_SIZE {
                            return Err(AleError::InvalidPacketLength(header.packet_length));
                        }
                        // User data length = packet_length - 8 (the checksum-covered header fields)
                        let payload_len = header.packet_length as usize - ALE_CHECKSUM_COVERED_SIZE;
                        if payload_len > ALE_MAX_USER_DATA {
                            return Err(AleError::PayloadTooLarge(payload_len));
                        }

                        if payload_len == 0 {
                            frames.push(AleFrame {
                                header,
                                user_data: Vec::new(),
                            });
                            self.header_pos = 0;
                        } else {
                            self.payload_buf.resize(payload_len, 0);
                            self.payload_pos = 0;
                            self.expected_payload_len = payload_len;
                            self.state = AleReadState::ReadingPayload { header };
                        }
                    }
                }
                AleReadState::ReadingPayload { header } => {
                    let need = self.expected_payload_len - self.payload_pos;
                    let avail = data.len() - pos;
                    let copy = need.min(avail);
                    self.payload_buf[self.payload_pos..self.payload_pos + copy]
                        .copy_from_slice(&data[pos..pos + copy]);
                    self.payload_pos += copy;
                    pos += copy;

                    if self.payload_pos == self.expected_payload_len {
                        // Clone the header out of the state (a cheap `Clone` of 9
                        // scalar fields) and transition back, without a
                        // `mem::replace` + impossible-`unreachable!()` arm (DP-14).
                        let header = header.clone();
                        self.state = AleReadState::ReadingHeader;
                        frames.push(AleFrame {
                            header,
                            user_data: self.payload_buf[..self.expected_payload_len].to_vec(),
                        });
                        self.header_pos = 0;
                        self.payload_pos = 0;
                    }
                }
            }
        }

        Ok(frames)
    }
}

// =========================================================================================
//                            ALE CONNECTION HANDSHAKE HELPERS
// =========================================================================================

/// AU1 connection information (Subset-098 §6.5.2.4.2).
#[derive(Debug, Clone)]
pub struct AleAu1Info {
    pub calling_etcs_id: u32,
    pub called_etcs_id: u32,
    pub class_of_service: u8,
}

impl AleAu1Info {
    /// Encode AU1 connection info into the user data portion (9 bytes + optional SaPDU).
    pub fn encode(&self, sapdu: &[u8]) -> Vec<u8> {
        let mut buf = Vec::with_capacity(9 + sapdu.len());
        buf.extend_from_slice(&self.calling_etcs_id.to_be_bytes());
        buf.extend_from_slice(&self.called_etcs_id.to_be_bytes());
        buf.push(self.class_of_service);
        buf.extend_from_slice(sapdu);
        buf
    }

    /// Decode AU1 connection info from user data.
    pub fn decode(data: &[u8]) -> Option<(Self, &[u8])> {
        if data.len() < 9 {
            return None;
        }
        let calling = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
        let called = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
        let class = data[8];
        Some((
            Self {
                calling_etcs_id: calling,
                called_etcs_id: called,
                class_of_service: class,
            },
            &data[9..],
        ))
    }
}

/// AU2 connection info (Subset-098 §6.5.2.4.7).
#[derive(Debug, Clone)]
pub struct AleAu2Info {
    pub responding_etcs_id: u32,
}

impl AleAu2Info {
    pub fn encode(&self, sapdu: &[u8]) -> Vec<u8> {
        let mut buf = Vec::with_capacity(4 + sapdu.len());
        buf.extend_from_slice(&self.responding_etcs_id.to_be_bytes());
        buf.extend_from_slice(sapdu);
        buf
    }

    pub fn decode(data: &[u8]) -> Option<(Self, &[u8])> {
        if data.len() < 4 {
            return None;
        }
        let id = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
        Some((
            Self {
                responding_etcs_id: id,
            },
            &data[4..],
        ))
    }
}

// =========================================================================================
//                                       TESTS
// =========================================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// Test vectors from Subset-098 v3.0.0, Table 14 (§7.5).
    #[test]
    fn test_crc_ccitt_subset098_vectors() {
        // Row 1: 001E 01 1A 0000 01 01 -> checksum 1089
        let input1 = [0x00, 0x1E, 0x01, 0x1A, 0x00, 0x00, 0x01, 0x01];
        assert_eq!(crc_ccitt(&input1), 0x1089, "vector 1");

        // Row 2: 0021 01 1A 0000 01 02 -> checksum F38E
        let input2 = [0x00, 0x21, 0x01, 0x1A, 0x00, 0x00, 0x01, 0x02];
        assert_eq!(crc_ccitt(&input2), 0xF38E, "vector 2");

        // Row 3: 0011 01 1A 0001 01 03 -> checksum 8D12
        let input3 = [0x00, 0x11, 0x01, 0x1A, 0x00, 0x01, 0x01, 0x03];
        assert_eq!(crc_ccitt(&input3), 0x8D12, "vector 3");

        // Row 4: 002A 01 1A 0002 01 03 -> checksum C6E0
        let input4 = [0x00, 0x2A, 0x01, 0x1A, 0x00, 0x02, 0x01, 0x03];
        assert_eq!(crc_ccitt(&input4), 0xC6E0, "vector 4");

        // Row 5: 000B 01 1A 0003 01 04 -> checksum 57A0
        let input5 = [0x00, 0x0B, 0x01, 0x1A, 0x00, 0x03, 0x01, 0x04];
        assert_eq!(crc_ccitt(&input5), 0x57A0, "vector 5");
    }

    #[test]
    fn test_header_roundtrip() {
        let header =
            AleHeader::build(ALE_VERSION, 0x1A, 42, ALE_NR_FLAG_NORMAL, ALE_PKT_DT, 100).unwrap();
        let encoded = header.encode();
        let decoded = AleHeader::decode(&encoded).expect("decode should succeed");
        assert_eq!(decoded.version, ALE_VERSION);
        assert_eq!(decoded.app_type, 0x1A);
        assert_eq!(decoded.t_sequence, 42);
        assert_eq!(decoded.nr_flag, ALE_NR_FLAG_NORMAL);
        assert_eq!(decoded.packet_type, ALE_PKT_DT);
        assert_eq!(decoded.checksum, header.checksum);
        // packet_length = 8 (header after PktLen) + 100 (user data) = 108
        assert_eq!(decoded.packet_length, 108);
    }

    // DP-14: `build` rejects an oversize payload instead of silently truncating
    // packet_length via `as u16`.
    #[test]
    fn test_build_rejects_oversize() {
        let err = AleHeader::build(
            ALE_VERSION,
            0x1A,
            0,
            ALE_NR_FLAG_NORMAL,
            ALE_PKT_DT,
            ALE_MAX_USER_DATA + 1,
        );
        assert!(matches!(err, Err(AleError::PayloadTooLarge(n)) if n == ALE_MAX_USER_DATA + 1));
    }

    #[test]
    fn test_build_accepts_max_payload() {
        let h = AleHeader::build(
            ALE_VERSION,
            0x1A,
            0,
            ALE_NR_FLAG_NORMAL,
            ALE_PKT_DT,
            ALE_MAX_USER_DATA,
        )
        .expect("max payload must build");
        assert_eq!(
            h.packet_length as usize,
            ALE_CHECKSUM_COVERED_SIZE + ALE_MAX_USER_DATA
        );
    }

    #[test]
    fn test_checksum_failure_detected() {
        let header =
            AleHeader::build(ALE_VERSION, 0x1A, 0, ALE_NR_FLAG_NORMAL, ALE_PKT_AU1, 20).unwrap();
        let mut encoded = header.encode();
        // Corrupt one byte
        encoded[3] ^= 0xFF;
        let result = AleHeader::decode(&encoded);
        assert!(
            matches!(result, Err(AleError::ChecksumMismatch { .. })),
            "should detect checksum mismatch"
        );
    }

    #[test]
    fn test_frame_writer_reader_roundtrip() {
        let mut output = Vec::new();
        let mut writer = AleFrameWriter::new(0x1A);

        let payload1 = b"Hello, EuroRadio!";
        let payload2 = b"Second message";

        writer
            .write_alepkt(&mut output, ALE_PKT_DT, payload1)
            .unwrap();
        writer
            .write_alepkt(&mut output, ALE_PKT_DT, payload2)
            .unwrap();

        let mut reader = AleFrameReader::new();
        let frames = reader.feed(&output).expect("feed should succeed");
        assert_eq!(frames.len(), 2);
        assert_eq!(frames[0].user_data, payload1);
        assert_eq!(frames[0].header.packet_type, ALE_PKT_DT);
        assert_eq!(frames[0].header.t_sequence, 0);
        assert_eq!(frames[1].user_data, payload2);
        assert_eq!(frames[1].header.t_sequence, 1);
    }

    #[test]
    fn test_frame_reader_partial_feed() {
        let mut output = Vec::new();
        let mut writer = AleFrameWriter::new(0x1A);
        let payload = b"Test partial read across TCP segments";
        writer
            .write_alepkt(&mut output, ALE_PKT_DT, payload)
            .unwrap();

        let mut reader = AleFrameReader::new();

        // Feed in tiny chunks (simulating TCP segmentation)
        let mut all_frames = Vec::new();
        for chunk in output.chunks(3) {
            let frames = reader.feed(chunk).expect("feed should succeed");
            all_frames.extend(frames);
        }

        assert_eq!(all_frames.len(), 1);
        assert_eq!(all_frames[0].user_data, payload);
    }

    #[test]
    fn test_sequence_number_wrapping() {
        let mut writer = AleFrameWriter::new(0x1A);
        // Artificially set sequence near max
        writer.t_sequence = 65534;

        let mut output = Vec::new();
        writer.write_alepkt(&mut output, ALE_PKT_DT, b"a").unwrap();
        assert_eq!(writer.t_sequence(), 65535);

        writer.write_alepkt(&mut output, ALE_PKT_DT, b"b").unwrap();
        assert_eq!(writer.t_sequence(), 0); // Wrapped

        writer.write_alepkt(&mut output, ALE_PKT_DT, b"c").unwrap();
        assert_eq!(writer.t_sequence(), 1);

        // Verify the encoded frames have correct sequences
        let mut reader = AleFrameReader::new();
        let frames = reader.feed(&output).unwrap();
        assert_eq!(frames.len(), 3);
        assert_eq!(frames[0].header.t_sequence, 65534);
        assert_eq!(frames[1].header.t_sequence, 65535);
        assert_eq!(frames[2].header.t_sequence, 0);
    }

    #[test]
    fn test_au1_au2_sequence_always_zero() {
        let mut writer = AleFrameWriter::new(0x1A);
        writer.t_sequence = 42; // Non-zero starting value

        let mut output = Vec::new();
        writer
            .write_alepkt(&mut output, ALE_PKT_AU1, b"au1data")
            .unwrap();
        // AU1 carries value 0 but still advances the counter (§6.5.3.3.2.1)
        assert_eq!(writer.t_sequence(), 43);

        writer
            .write_alepkt(&mut output, ALE_PKT_AU2, b"au2data")
            .unwrap();
        assert_eq!(writer.t_sequence(), 44);

        let mut reader = AleFrameReader::new();
        let frames = reader.feed(&output).unwrap();
        assert_eq!(frames[0].header.t_sequence, 0); // AU1 always carries 0
        assert_eq!(frames[1].header.t_sequence, 0); // AU2 always carries 0
    }

    #[test]
    fn test_au1_info_roundtrip() {
        let info = AleAu1Info {
            calling_etcs_id: 0x12345678,
            called_etcs_id: 0xABCDEF01,
            class_of_service: ALE_CLASS_D,
        };
        let encoded = info.encode(b"sapdu");
        let (decoded, sapdu) = AleAu1Info::decode(&encoded).unwrap();
        assert_eq!(decoded.calling_etcs_id, 0x12345678);
        assert_eq!(decoded.called_etcs_id, 0xABCDEF01);
        assert_eq!(decoded.class_of_service, ALE_CLASS_D);
        assert_eq!(sapdu, b"sapdu");
    }

    #[test]
    fn test_payload_too_large() {
        let mut output = Vec::new();
        let mut writer = AleFrameWriter::new(0x1A);
        let big = vec![0u8; ALE_MAX_USER_DATA + 1];
        let result = writer.write_alepkt(&mut output, ALE_PKT_DT, &big);
        assert!(matches!(result, Err(AleError::PayloadTooLarge(_))));
    }

    #[test]
    fn test_au2_info_roundtrip() {
        let info = AleAu2Info {
            responding_etcs_id: 0xDEADBEEF,
        };
        let encoded = info.encode(b"au2sapdu");
        let (decoded, sapdu) = AleAu2Info::decode(&encoded).unwrap();
        assert_eq!(decoded.responding_etcs_id, 0xDEADBEEF);
        assert_eq!(sapdu, b"au2sapdu");
    }

    #[test]
    fn test_au1_decode_too_short() {
        assert!(AleAu1Info::decode(&[0; 8]).is_none());
        assert!(AleAu1Info::decode(&[]).is_none());
    }

    #[test]
    fn test_au2_decode_too_short() {
        assert!(AleAu2Info::decode(&[0; 3]).is_none());
        assert!(AleAu2Info::decode(&[]).is_none());
    }

    #[test]
    fn test_invalid_packet_type() {
        let mut buf = [0u8; ALE_HEADER_SIZE];
        // Build a valid header, then overwrite the packet type with an invalid value
        buf[0..2].copy_from_slice(&8u16.to_be_bytes()); // packet_length
        buf[2] = ALE_VERSION;
        buf[3] = 0x1A;
        buf[4..6].copy_from_slice(&0u16.to_be_bytes());
        buf[6] = ALE_NR_FLAG_NORMAL;
        buf[7] = 0xFF; // invalid packet type
        let cksum = crc_ccitt(&buf[0..8]);
        buf[8..10].copy_from_slice(&cksum.to_be_bytes());

        let result = AleHeader::decode(&buf);
        assert!(
            matches!(result, Err(AleError::InvalidPacketType(0xFF))),
            "should reject invalid packet type"
        );
    }

    #[test]
    fn test_di_packet_increments_sequence() {
        let mut writer = AleFrameWriter::new(0x1A);
        let mut output = Vec::new();

        writer
            .write_alepkt(&mut output, ALE_PKT_DT, b"data")
            .unwrap();
        assert_eq!(writer.t_sequence(), 1);

        writer.write_alepkt(&mut output, ALE_PKT_DI, b"").unwrap();
        assert_eq!(writer.t_sequence(), 2);

        let mut reader = AleFrameReader::new();
        let frames = reader.feed(&output).unwrap();
        assert_eq!(frames.len(), 2);
        assert_eq!(frames[0].header.packet_type, ALE_PKT_DT);
        assert_eq!(frames[1].header.packet_type, ALE_PKT_DI);
        assert_eq!(frames[1].header.t_sequence, 1);
    }

    #[test]
    fn test_multiple_frames_across_chunk_boundary() {
        let mut output = Vec::new();
        let mut writer = AleFrameWriter::new(0x1A);

        writer
            .write_alepkt(&mut output, ALE_PKT_DT, b"first")
            .unwrap();
        writer
            .write_alepkt(&mut output, ALE_PKT_DT, b"second")
            .unwrap();
        writer
            .write_alepkt(&mut output, ALE_PKT_DT, b"third")
            .unwrap();

        // Feed in 7-byte chunks (splits frames mid-header and mid-payload)
        let mut reader = AleFrameReader::new();
        let mut all_frames = Vec::new();
        for chunk in output.chunks(7) {
            let frames = reader.feed(chunk).unwrap();
            all_frames.extend(frames);
        }

        assert_eq!(all_frames.len(), 3);
        assert_eq!(all_frames[0].user_data, b"first");
        assert_eq!(all_frames[1].user_data, b"second");
        assert_eq!(all_frames[2].user_data, b"third");
    }

    #[test]
    fn test_default_frame_reader() {
        let reader: AleFrameReader = Default::default();
        assert_eq!(reader.header_pos, 0);
    }

    #[test]
    fn test_reject_too_small_packet_length() {
        let mut buf = [0u8; ALE_HEADER_SIZE];
        buf[0..2].copy_from_slice(&7u16.to_be_bytes()); // invalid: packet_length < 8
        buf[2] = ALE_VERSION;
        buf[3] = 0x1A;
        buf[4..6].copy_from_slice(&0u16.to_be_bytes());
        buf[6] = ALE_NR_FLAG_NORMAL;
        buf[7] = ALE_PKT_DT;
        let cksum = crc_ccitt(&buf[0..8]);
        buf[8..10].copy_from_slice(&cksum.to_be_bytes());

        // Header decode itself succeeds (it doesn't validate packet_length range)
        let header = AleHeader::decode(&buf).unwrap();
        assert_eq!(header.packet_length, 7);

        // But feed() must reject it before the subtraction can underflow
        let mut reader = AleFrameReader::new();
        let result = reader.feed(&buf);
        assert!(
            matches!(result, Err(AleError::InvalidPacketLength(7))),
            "should reject packet_length < 8, got: {:?}",
            result
        );
    }

    #[test]
    fn test_frame_roundtrip_packet_length_equals_8_plus_payload() {
        let mut output = Vec::new();
        let mut writer = AleFrameWriter::new(0x1A);

        let payloads: &[&[u8]] = &[b"", b"short", &[0xAB; 200]];
        for payload in payloads {
            writer
                .write_alepkt(&mut output, ALE_PKT_DT, payload)
                .unwrap();
        }

        let mut reader = AleFrameReader::new();
        let frames = reader.feed(&output).unwrap();
        assert_eq!(frames.len(), 3);

        for (frame, payload) in frames.iter().zip(payloads.iter()) {
            assert_eq!(
                frame.header.packet_length as usize,
                8 + payload.len(),
                "packet_length must equal 8 + user_data_len for payload of {} bytes",
                payload.len()
            );
            assert_eq!(frame.user_data, *payload);
        }
    }
}

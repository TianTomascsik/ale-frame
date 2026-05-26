# ale-frame

ALEPKT framing for EuroRadio (ERTMS/ETCS) communication, implemented in Rust.

Provides streaming encode and decode of ALE packets over TCP as specified in
**UNISIG Subset-098 v3.0.0** (§6.4.5) and **Subset-037 v3.2.0** (§8.3.2).

## Background

In the European Train Control System (ETCS), trackside and on-board equipment
communicate safety-critical messages through the **EuroRadio** protocol stack.
The Adaptation Layer Entity (ALE) sits between the EuroRadio Safety Layer and
TCP, converting discrete Safety Layer PDUs (SaPDUs) into a framed byte stream
suitable for transport over TCP connections.

### Why ALE exists

TCP provides a continuous byte stream with no message boundaries, whereas the
EuroRadio Safety Layer (ISO Transport Class 2 / X.214 emulation) operates on
discrete protocol data units. The ALE bridges this gap using a simple
length-prefixed packetisation scheme (Subset-098 §6.4.5.1.1–§6.4.5.1.3):

> "One of the fundamental differences between the TCP and the ISO Transport
> Service is that the TCP manages a continuous stream of octets, with no
> explicit boundaries whereas TP2 handles well-bounded TPDUs."

The ALE reassembles each information packet previously embedded in the
continuous stream of bytes coming from the TCP level.

### Protocol stack position

```text
┌─────────────────────────────────┐
│  Application (ATP / RBC-RBC)    │
├─────────────────────────────────┤
│  EuroRadio Safety Layer (SaPDU) │
├─────────────────────────────────┤
│  ALE  (ALEPKT framing)  ← this crate
├─────────────────────────────────┤
│  TCP                            │
├─────────────────────────────────┤
│  IP                             │
└─────────────────────────────────┘
```

## ALEPKT Wire Format

Each ALE packet (ALEPKT) is a variable-length object composed of an integral
number of octets in **Big-Endian** byte order (Subset-098 §6.4.5.1.4). It
consists of a 10-byte Packet Header followed by optional User Data:

```text
┌───────────────┬─────────┬──────────┬───────────┬──────────┬──────────┬──────────┬───────────┐
│ Packet Length │ Version │ App Type │ T-Seq Num │ N/R Flag │ Pkt Type │ Checksum │ User Data │
│   2 octets    │ 1 octet │ 1 octet  │ 2 octets  │ 1 octet  │ 1 octet  │ 2 octets │ variable  │
└───────────────┴─────────┴──────────┴───────────┴──────────┴──────────┴──────────┴───────────┘
```

### Header field descriptions (Subset-098 §6.4.5.1.5, Table 6)

| Field | Size | Description |
|-------|------|-------------|
| **Packet Length** | 2 octets | Length of the entire ALEPKT *excluding* this 2-byte field itself. |
| **Version** | 1 octet | Identifies the facilities offered by the Adaptation Layer. May be ignored by the receiver. |
| **Application Type** | 1 octet | Identifies the application type (§6.4.4.1 / Subset-037 §8.2.4.6.4). First 5 bits = main type, last 3 bits = minor type. May be ignored by the receiver. |
| **T-Sequence Number** | 2 octets | Transport Sequence Number used by the receiving ALE for duplicate suppression when switching between two TCP connections (Class D). Initialised to 0 before connection starts; AU1/AU2 always carry value 0. Incremented by 1 for each subsequent ALEPKT sent. Wraps from 65535 → 0. |
| **N/R Flag** | 1 octet | Specifies whether the ALEPKT is sent on the Normal (1) or Redundant (0) link. Attribution is fixed during configuration. For single-link operation: always 1. |
| **Packet Type** | 1 octet | Determines the type of packet and the action the ALE takes on receipt (see table below). |
| **Checksum** | 2 octets | CRC-CCITT over the preceding 8 bytes (Packet Length through Packet Type). A failed checksum causes the ALE to disconnect and re-connect the TCP connection to maintain ALEPKT boundary integrity. |
| **User Data** | variable | TS-User data (SaPDU). Maximum 65,000 bytes (§6.5.3.1.3). |

### Checksum algorithm (Subset-098 §6.4.5.1.5 / Table 6 / §7.5)

- Generator polynomial: CRC-CCITT $x^{16} + x^{12} + x^5 + 1$ (0x1021)
- Initial value: 0xFFFF
- **No** final 1's-complement inversion (neither sender nor receiver)
- The highest term ($x^{16}$) corresponds to the LSB of the Checksum field
- Computed over 8 bytes: PacketLength(2) + Version(1) + AppType(1) + TSeqNum(2) + NR(1) + PktType(1)
- Specified per ISO/IEC 3309

**Official test vectors** (Subset-098 §7.5, Table 14):

| Packet Length | Version | App Type | T-Seq | N/R | Pkt Type | Checksum |
|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| 001E | 01 | 1A | 0000 | 01 | 01 | **1089** |
| 0021 | 01 | 1A | 0000 | 01 | 02 | **F38E** |
| 0011 | 01 | 1A | 0001 | 01 | 03 | **8D12** |
| 002A | 01 | 1A | 0002 | 01 | 03 | **C6E0** |
| 000B | 01 | 1A | 0003 | 01 | 04 | **57A0** |

## Packet Types

Summary of all ALEPKT types (Subset-098 §6.6.3, Table 10):

| Type | Name | Scope | User Data | Classes |
|:----:|------|-------|-----------|:-------:|
| 1 | **AU1** (CR) | Request a connection to peer | Calling ETCS-ID (4) + Called ETCS-ID (4) + Class of Service (1) + AU1 SaPDU | A & D |
| 2 | **AU2** (CC) | Accept a connection from peer | Responding ETCS-ID (4) + AU2 SaPDU | A & D |
| 3 | **DT** | Transfer user data | SaPDU | A & D |
| 4 | **DI** | Release a connection (non-disruptive disconnect) | DI SaPDU | A & D |
| 251 | SwitchN2R | Switch data traffic to redundant link | None or SaPDU | A only |
| 253 | SwitchR2N | Switch data traffic to normal link | None or SaPDU | A only |
| 254 | KANA | Keep-alive on non-active link | None | A only |
| 255 | KAA | Keep-alive on active link | None | A only |

This crate implements types 1–4 (mandatory for both Class A and Class D).

## Connection Lifecycle

### Connection establishment (Subset-098 §6.5.2)

```text
  Initiator                                  Responder
     │                                          │
     │──── TCP 3-way handshake ────────────────→│
     │                                          │
     │──── AU1 ALEPKT (T-Seq=0) ───────────────→│  T-Connect.Request
     │                                          │  T-Connect.Indication
     │←─── AU2 ALEPKT (T-Seq=0) ────────────────│  T-Connect.Response
     │     T-Connect.Confirmation               │
     │                                          │
     │──── DT  ALEPKT (T-Seq=1, AU3 SaPDU) ────→│  Safe connection setup
     │←─── DT  ALEPKT (T-Seq=1, AR  SaPDU) ─────│  (EuroRadio safety handshake)
     │                                          │
```

- AU1/AU2 always have T-Sequence = 0 (§6.5.2.6.4)
- The counter is initialised to 0 before the connection procedure starts
- After AU1/AU2, each subsequent DT/DI increments T-Sequence by 1

### Data transfer (Subset-098 §6.5.3)

- DT ALEPKTs carry SaPDUs in the User Data field
- T-Sequence Number increments by 1 per ALEPKT sent (§6.5.3.3.2.1)
- Wraps from 65535 → 0 (§6.5.3.3.2.2)
- Maximum User Data size: 65,000 bytes (§6.5.3.1.3)

### Connection release (Subset-098 §6.5.4)

**Non-disruptive** (normal): The sender transmits a DI ALEPKT, waits for all
data to be delivered, then issues TCP_CLOSE. The remote ALE receives
TCP_CLOSED and issues T-Disconnect.Indication to its user.

**Disruptive** (failure): The ALE issues T-Disconnect.Indication to both TS-Users
with appropriate reason/sub-reason codes. No DI ALEPKT is guaranteed.

## Class D Operation (Subset-098 §6.6.2)

Class D is the **mandatory** class of service (§6.3.2.1.3). Key properties:

- **Dual-link (full spec):** All ALEPKTs are sent on *both* TCP connections
  simultaneously. The receiver uses T-Sequence Number for duplicate suppression.
- **Single-link (this crate):** Operates on one TCP connection with N/R flag = 1
  (§6.6.2.1.3). No redundancy management. This is explicitly permitted by the
  specification and is the profile used for OBU-to-RBC communication
  (Subset-037 §6.3.2.1.4).
- Class D coded value: 0x03 (Subset-098 §6.6.2.1.6) — *note: in Subset-037
  the AU1 Class of Service field uses 0x01 for "Class D single link"*
- Connection monitoring via standard TCP Keep-Alive (§6.6.2.4)
- On receiver side: ALEPKTs with T-Sequence ≤ last delivered are discarded (§6.6.2.2.3)

### Duplicate suppression (full Class D, not yet implemented)

The receiver observes ALEPKTs on both TCP connections and discards any packet
whose T-Sequence Number has already been delivered to the TS-User. Two
behaviours are configurable (§6.6.2.2.4):

- **(a)** Accept any T-Seq greater than last delivered (tolerates gaps)
- **(b)** Accept only T-Seq = last + 1 (strict, no gaps allowed)

## OBU-to-RBC Profile (Subset-037 §8.3.2)

Subset-037 adapts Subset-098 for on-board (OBU) to trackside (RBC)
communication over GPRS/PS:

- Only Class D is supported (§6.3.2.1.3)
- One single physical link, one TCP connection, no redundancy (§6.3.2.1.4)
- N/R Flag always = 1
- Listening TCP port: **7911** (§8.3.2.4.1)
- Address resolution via DNS: format `id<ETCS-ID>.ty<type>.etcs` (§8.3.2.3.5)
- Connection monitoring via standard TCP Keep-Alive (§8.3.2.5.1)
- ALE functions (§8.3.2.1.1):
  - Adaptation between EuroRadio Safety Layer and TCP layer
  - Establishment and release of the TCP connection
  - Conversion between Safety Layer packets to/from TCP stream
  - Monitoring of channel availability

## Features

- **Streaming reassembly** — handles arbitrary TCP chunking with stateful
  accumulation of partial headers and payloads
- **Class D support (single-link profile)** — single TCP connection with
  transport sequence numbering. Full Subset-098 Class D (dual redundant TCP
  links with duplicate T-Sequence suppression) is not yet implemented.
- **Connection handshake** — AU1 (Connection Request) and AU2 (Connection
  Confirm) encoding/decoding with ETCS-ID fields
- **CRC-CCITT validation** — verified against all official test vectors from
  Subset-098 Table 14
- **Zero dependencies** — only uses `std`

## Usage

```rust
use ale_frame::{AleFrameWriter, AleFrameReader, ALE_PKT_DT};

// Create a writer with application type 0x1A (RBC-RBC)
let mut writer = AleFrameWriter::new(0x1A);
let mut buf = Vec::new();

// Write a Data Transfer packet
writer.write_alepkt(&mut buf, ALE_PKT_DT, b"payload").unwrap();

// Read it back from the TCP stream
let mut reader = AleFrameReader::new();
let frames = reader.feed(&buf).unwrap();
assert_eq!(frames[0].user_data, b"payload");
assert_eq!(frames[0].header.t_sequence, 0);
```

### Connection handshake

```rust
use ale_frame::*;

let mut writer = AleFrameWriter::new(0x1A);
let mut buf = Vec::new();

// Encode an AU1 (Connection Request)
let au1 = AleAu1Info {
    calling_etcs_id: 0x00001234,
    called_etcs_id:  0x00005678,
    class_of_service: ALE_CLASS_D,
};
let user_data = au1.encode(b"");  // no SaPDU for this example
writer.write_alepkt(&mut buf, ALE_PKT_AU1, &user_data).unwrap();

// Decode on the receiving side
let mut reader = AleFrameReader::new();
let frames = reader.feed(&buf).unwrap();
let (info, _sapdu) = AleAu1Info::decode(&frames[0].user_data).unwrap();
assert_eq!(info.calling_etcs_id, 0x00001234);
```

## Error handling (Subset-098 §6.7)

- **Checksum failure:** The ALE disconnects and re-connects the TCP connection
  to ensure ALEPKT boundaries are maintained (§6.7.1.1.3).
- **Invalid Packet Type:** A received ALEPKT containing a Packet Type not
  specified for the selected Class of Service causes the ALE to discard the
  packet. The receiving ALE may also close the TCP connection (Table 6).
- **Payload too large:** User Data exceeding 65,000 bytes is rejected.

## Specification references

| Document | Section | Topic |
|----------|---------|-------|
| UNISIG Subset-098 v3.0.0 | §6.3.1 | TCP equivalence to Transport Class 2 |
| UNISIG Subset-098 v3.0.0 | §6.3.2 | Class of Service (A and D) |
| UNISIG Subset-098 v3.0.0 | §6.4.3 | Mapping of X.214 primitives to TCP |
| UNISIG Subset-098 v3.0.0 | §6.4.5 | ALEPKT header format and checksum |
| UNISIG Subset-098 v3.0.0 | §6.5.1 | Using TCP/IP to provide ISO Transport Class 2 |
| UNISIG Subset-098 v3.0.0 | §6.5.2 | ALE operation — connection establishment (AU1/AU2) |
| UNISIG Subset-098 v3.0.0 | §6.5.3 | Data transfer (DT), T-Sequence semantics |
| UNISIG Subset-098 v3.0.0 | §6.5.4 | Connection release (DI), non-disruptive/disruptive |
| UNISIG Subset-098 v3.0.0 | §6.6.2 | Class D operation and redundancy |
| UNISIG Subset-098 v3.0.0 | §6.6.3 | Summary of all ALEPKT types (Table 10) |
| UNISIG Subset-098 v3.0.0 | §6.7 | Error handling |
| UNISIG Subset-098 v3.0.0 | §7.5 (Table 14) | CRC-CCITT test vectors |
| UNISIG Subset-037 v3.2.0 | §8.3.2 | OBU-to-RBC ALE adaptation over PS/GPRS |
| UNISIG Subset-037 v3.2.0 | §8.3.2.4 | Listening port (7911) |
| UNISIG Subset-037 v3.2.0 | Table 41 | Applicability conditions of Subset-098 for OBU |

## Testing

```sh
cargo test
```

The test suite includes CRC validation against the official Subset-098 test
vectors, header encode/decode roundtrips, streaming reassembly with simulated
TCP segmentation, sequence number wrapping, and connection handshake encoding.

## License

Licensed under the MIT License. See [LICENSE](LICENSE) for details.

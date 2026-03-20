# ale-frame

ALEPKT framing for EuroRadio (ERTMS/ETCS) communication, implemented in Rust.

Provides streaming encode and decode of ALE packets over TCP as specified in
**UNISIG Subset-098 v3.0.0** (§6.4.5) and **Subset-037 v3.2.0** (§8.3.2).

## Background

In the European Train Control System (ETCS), trackside and on-board equipment
communicate safety-critical messages through the **EuroRadio** protocol stack.
The Adaptation Layer Entity (ALE) sits between the EuroRadio Safety Layer and
TCP, converting discrete Safety Layer PDUs into a framed byte stream suitable
for transport over TCP connections.

Each ALE packet (ALEPKT) consists of a 10-byte header followed by variable-length
user data:

```text
┌───────────────┬─────────┬──────────┬───────────┬──────────┬──────────┬──────────┬───────────┐
│ Packet Length │ Version │ App Type │ T-Seq Num │ N/R Flag │ Pkt Type │ Checksum │ User Data │
│   2 octets    │ 1 octet │ 1 octet  │ 2 octets  │ 1 octet  │ 1 octet  │ 2 octets │ variable  │
└───────────────┴─────────┴──────────┴───────────┴──────────┴──────────┴──────────┴───────────┘
```

The header checksum uses CRC-CCITT (polynomial 0x1021, initial value 0xFFFF, no
final inversion) per ISO/IEC 3309.

## Features

- **Streaming reassembly** -- handles arbitrary TCP chunking with zero-copy
  accumulation of partial headers and payloads
- **Class D support (single-link profile)** -- single TCP connection with transport
  sequence numbering. Note: full Subset-098 Class D requires dual redundant TCP
  links with duplicate T-Sequence suppression, which is not yet implemented.
- **Connection handshake** -- AU1 (Connection Request) and AU2 (Connection
  Confirm) encoding/decoding with ETCS-ID fields
- **CRC-CCITT validation** -- verified against official test vectors from
  Subset-098 Table 14
- **Zero dependencies** -- only uses `std`

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

## Specification references

| Document | Section | Topic |
|----------|---------|-------|
| UNISIG Subset-098 v3.0.0 | §6.4.5 | ALEPKT header format and checksum |
| UNISIG Subset-098 v3.0.0 | §6.5 | Packet type definitions |
| UNISIG Subset-098 v3.0.0 | §6.6 | Class D operation |
| UNISIG Subset-098 v3.0.0 | §7.5 (Table 14) | CRC-CCITT test vectors |
| UNISIG Subset-037 v3.2.0 | §8.3.2 | OBU-to-RBC ALE adaptation |

## Testing

```sh
cargo test
```

The test suite includes CRC validation against the official Subset-098 test
vectors, header encode/decode roundtrips, streaming reassembly with simulated
TCP segmentation, sequence number wrapping, and connection handshake encoding.

## License

Licensed under the MIT License. See [LICENSE](LICENSE) for details.

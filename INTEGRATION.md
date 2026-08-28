# Integrating ale-frame

This guide explains how to add `ale-frame` to your Rust project and implement
ALEPKT communication over TCP.

## Adding the dependency

### From the git repository

```toml
[dependencies]
ale-frame = { git = "https://github.com/TianTomascsik/ale-frame.git", tag = "v0.2.0" }
```

Or with a renamed import:

```toml
[dependencies]
ale_pipe = { git = "https://github.com/TianTomascsik/ale-frame.git", tag = "v0.2.0", package = "ale-frame" }
```

### As a path dependency (monorepo / git submodule)

```toml
[dependencies]
ale-frame = { path = "../ale-frame" }
```

### Minimum Rust version

`ale-frame` requires **Rust 1.65+** and has **zero external dependencies** —
it only uses `std`.

---

## Core concepts

| Struct | Role |
|--------|------|
| `AleFrameWriter` | Stateful encoder — serialises ALEPKTs with auto-incrementing T-Sequence |
| `AleFrameReader` | Streaming decoder — reassembles ALEPKTs from arbitrarily chunked TCP data |
| `AleFrame` | A complete decoded frame (header + user data) |
| `AleHeader` | The 10-byte ALEPKT header (packet length, version, app type, T-seq, N/R, type, CRC) |
| `AleAu1Info` | Encodes/decodes AU1 connection info (calling/called ETCS-ID, class of service) |
| `AleAu2Info` | Encodes/decodes AU2 connection info (responding ETCS-ID) |

---

## Step-by-step integration

### 1. Create writer and reader

Each TCP connection needs its own writer (tracks T-Sequence state) and reader
(tracks reassembly state):

```rust
use ale_frame::{AleFrameWriter, AleFrameReader};

// Application type identifies the protocol (e.g., 0x1A = RBC application)
let mut writer = AleFrameWriter::new(0x1A);
let mut reader = AleFrameReader::new();
```

### 2. Connection establishment (AU1/AU2 handshake)

**Initiator sends AU1:**

```rust
use ale_frame::*;

let au1 = AleAu1Info {
    calling_etcs_id: 0x0000_1234,  // your ETCS-ID
    called_etcs_id:  0x0000_5678,  // remote ETCS-ID
    class_of_service: ALE_CLASS_D, // mandatory class
};
let payload = au1.encode(b"");  // optionally include SaPDU bytes
writer.write_alepkt(&mut tcp_stream, ALE_PKT_AU1, &payload)?;
```

**Responder receives AU1 and sends AU2:**

```rust
let frame = read_one_frame(&mut tcp_stream, &mut reader); // see helper below
assert_eq!(frame.header.packet_type, ALE_PKT_AU1);

let (au1_info, sapdu) = AleAu1Info::decode(&frame.user_data)
    .expect("malformed AU1");

// Accept connection
let au2 = AleAu2Info { responding_etcs_id: my_etcs_id };
writer.write_alepkt(&mut tcp_stream, ALE_PKT_AU2, &au2.encode(b""))?;
```

### 3. Data transfer

```rust
// Send
writer.write_alepkt(&mut tcp_stream, ALE_PKT_DT, &sapdu_bytes)?;

// Receive — feed raw TCP bytes into the reader
let n = tcp_stream.read(&mut buf)?;
let frames = reader.feed(&buf[..n])?;
for frame in frames {
    // frame.header.t_sequence — use for duplicate detection (Class D)
    // frame.user_data — the SaPDU to pass to the Safety Layer
    process_sapdu(&frame.user_data);
}
```

### 4. Disconnect

```rust
// Non-disruptive disconnect (Subset-098 §6.5.4)
writer.write_alepkt(&mut tcp_stream, ALE_PKT_DI, b"")?;
// Wait for peer TCP_CLOSE, then close your end
```

---

## Reading frames from TCP

The `AleFrameReader` handles TCP's arbitrary chunking transparently. You just
need to feed it whatever bytes arrive:

```rust
use ale_frame::{AleFrame, AleFrameReader};
use std::io::Read;
use std::net::TcpStream;

/// Blocking helper: reads until one complete ALE frame arrives.
fn read_one_frame(stream: &mut TcpStream, reader: &mut AleFrameReader) -> AleFrame {
    let mut buf = [0u8; 4096];
    loop {
        let n = stream.read(&mut buf).expect("read failed");
        if n == 0 {
            panic!("connection closed");
        }
        let frames = reader.feed(&buf[..n]).expect("parse error");
        if let Some(frame) = frames.into_iter().next() {
            return frame;
        }
    }
}
```

> **Note:** In a real application you would use non-blocking I/O or an async
> runtime (tokio/mio). The `feed()` method works the same way — just pass
> whichever bytes you have available and collect completed frames.

---

## Integration with async runtimes (Tokio)

`ale-frame` is runtime-agnostic. For tokio integration:

```rust
use ale_frame::{AleFrameReader, AleFrameWriter, AleFrame, ALE_PKT_DT};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

async fn send_dt(stream: &mut TcpStream, writer: &mut AleFrameWriter, data: &[u8]) {
    let mut buf = Vec::new();
    writer.write_alepkt(&mut buf, ALE_PKT_DT, data).unwrap();
    stream.write_all(&buf).await.unwrap();
}

async fn recv_frames(stream: &mut TcpStream, reader: &mut AleFrameReader) -> Vec<AleFrame> {
    let mut buf = [0u8; 4096];
    let n = stream.read(&mut buf).await.unwrap();
    reader.feed(&buf[..n]).unwrap()
}
```

The pattern is: write into a `Vec<u8>` buffer first, then send asynchronously.

---

## Error handling

All errors are reported via `AleError`:

```rust
use ale_frame::AleError;

match reader.feed(&data) {
    Ok(frames) => { /* process frames */ }
    Err(AleError::ChecksumMismatch { expected, got }) => {
        // Per spec: disconnect and re-connect this TCP link
        eprintln!("CRC mismatch: expected 0x{:04X}, got 0x{:04X}", expected, got);
        reconnect();
    }
    Err(AleError::InvalidPacketType(t)) => {
        // Discard packet; optionally close connection
        eprintln!("unknown packet type: {}", t);
    }
    Err(AleError::InvalidPacketLength(n)) => {
        eprintln!("invalid packet length: {}", n);
        reconnect();
    }
    Err(AleError::PayloadTooLarge(n)) => {
        eprintln!("payload exceeds 65000 bytes: {}", n);
        reconnect();
    }
    Err(AleError::Io(e)) => {
        eprintln!("I/O error: {}", e);
    }
}
```

---

## T-Sequence handling for Class D duplicate suppression

If operating in full Class D (dual TCP links), track the last delivered
T-Sequence and discard duplicates:

```rust
let mut last_t_seq: Option<u16> = None;

for frame in reader.feed(&data)? {
    let seq = frame.header.t_sequence;
    let dominated = last_t_seq.map_or(false, |last| {
        // Handle wrapping: consider seq "old" if it's within the lower half
        seq == last || seq.wrapping_sub(last) > 32768
    });
    if dominated {
        continue; // duplicate — discard
    }
    last_t_seq = Some(seq);
    deliver_to_safety_layer(frame);
}
```

---

## Typical architecture patterns

### Pattern A: Thin wrapper (direct use)

```text
┌──────────────────┐       ┌──────────────────┐
│  Safety Layer    │       │  Safety Layer    │
│  (your code)     │       │  (your code)     │
├──────────────────┤       ├──────────────────┤
│  AleFrameWriter  │ TCP   │  AleFrameReader  │
│  AleFrameReader  │◄─────►│  AleFrameWriter  │
├──────────────────┤       ├──────────────────┤
│  TcpStream       │       │  TcpStream       │
└──────────────────┘       └──────────────────┘
```

### Pattern B: Channel-based (decoupled I/O)

```rust
// I/O thread feeds frames into a channel
let (tx, rx) = std::sync::mpsc::channel::<AleFrame>();
std::thread::spawn(move || {
    let mut reader = AleFrameReader::new();
    let mut buf = [0u8; 8192];
    loop {
        let n = stream.read(&mut buf).unwrap();
        for frame in reader.feed(&buf[..n]).unwrap() {
            tx.send(frame).unwrap();
        }
    }
});

// Application thread processes frames
for frame in rx {
    match frame.header.packet_type {
        ALE_PKT_DT => handle_data(frame.user_data),
        ALE_PKT_DI => break,
        _ => {}
    }
}
```

---

## Running the example

```sh
cd ale-frame
cargo run --example two_clients
```

This demonstrates a complete AU1→AU2→DT→DI exchange between two threads over
localhost TCP. See `examples/two_clients.rs` for the full annotated source.

---

## API reference

Generate local documentation:

```sh
cargo doc --open
```

## Specification references

| Document | Key sections |
|----------|-------------|
| UNISIG Subset-098 v3.0.0 | §6.4.5 (wire format), §6.5.2 (handshake), §6.5.3 (data), §6.5.4 (disconnect), §6.6.2 (Class D) |
| UNISIG Subset-037 v3.2.0 | §8.3.2 (OBU-to-RBC ALE adaptation) |

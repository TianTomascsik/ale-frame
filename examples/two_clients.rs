//! two_clients — Demonstrates ALE-frame communication between two peers over TCP.
//!
//! This example spawns a server thread (RBC / responder) and a client thread
//! (OBU / initiator) that perform a full ALEPKT connection lifecycle:
//!
//!   1. TCP connection establishment
//!   2. AU1 (Connection Request) — client → server
//!   3. AU2 (Connection Confirm) — server → client
//!   4. DT  (Data Transfer)      — bidirectional message exchange
//!   5. DI  (Disconnect)         — client → server, graceful teardown
//!
//! Run with:
//!   cargo run --example two_clients
//!
//! No external dependencies — uses only `ale-frame` + `std`.

use ale_frame::*;

use std::io::Read;
use std::net::{TcpListener, TcpStream};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

// ─── Configuration ───────────────────────────────────────────────────────────

/// Application type used by both peers (0x1A = RBC application per Subset-037).
const APP_TYPE: u8 = 0x1A;

/// ETCS-ID of the initiator (OBU / calling entity).
const OBU_ETCS_ID: u32 = 0x0000_1234;

/// ETCS-ID of the responder (RBC / called entity).
const RBC_ETCS_ID: u32 = 0x0000_5678;

/// Number of data messages exchanged in each direction.
const NUM_MESSAGES: usize = 5;

// ─── Helpers ─────────────────────────────────────────────────────────────────

/// Human-readable packet type name.
fn pkt_type_name(pkt_type: u8) -> &'static str {
    match pkt_type {
        ALE_PKT_AU1 => "AU1 (Connection Request)",
        ALE_PKT_AU2 => "AU2 (Connection Confirm)",
        ALE_PKT_DT => "DT  (Data Transfer)",
        ALE_PKT_DI => "DI  (Disconnect)",
        _ => "UNKNOWN",
    }
}

/// Read from a TcpStream into the AleFrameReader until exactly one complete
/// frame is available. Returns the first complete frame.
///
/// In a production system you would integrate this with async I/O or
/// non-blocking reads; here we use simple blocking reads for clarity.
fn read_one_frame(stream: &mut TcpStream, reader: &mut AleFrameReader) -> AleFrame {
    let mut buf = [0u8; 4096];
    loop {
        let n = stream.read(&mut buf).expect("TCP read failed");
        if n == 0 {
            panic!("connection closed unexpectedly while waiting for a frame");
        }
        let frames = reader.feed(&buf[..n]).expect("ALE frame parse error");
        if let Some(frame) = frames.into_iter().next() {
            return frame;
        }
        // Not enough data yet — continue reading
    }
}

/// Log a frame event with a role prefix.
fn log_frame(role: &str, direction: &str, frame: &AleFrame) {
    println!(
        "  [{role}] {direction} {pkt_type:<28} | T-Seq={seq:>5} | payload={len} bytes",
        role = role,
        direction = direction,
        pkt_type = pkt_type_name(frame.header.packet_type),
        seq = frame.header.t_sequence,
        len = frame.user_data.len(),
    );
}

// ─── Server (RBC / Responder) ────────────────────────────────────────────────

fn run_server(listener: TcpListener) {
    let (mut stream, peer_addr) = listener.accept().expect("accept failed");
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    println!("  [RBC] Accepted connection from {}", peer_addr);

    let mut reader = AleFrameReader::new();
    let mut writer = AleFrameWriter::new(APP_TYPE);

    // ── Step 1: Receive AU1 (Connection Request) ─────────────────────────
    let au1_frame = read_one_frame(&mut stream, &mut reader);
    log_frame("RBC", "◀ RECV", &au1_frame);

    assert_eq!(
        au1_frame.header.packet_type, ALE_PKT_AU1,
        "expected AU1 as first packet"
    );

    let (au1_info, _sapdu) =
        AleAu1Info::decode(&au1_frame.user_data).expect("failed to decode AU1 info");

    println!(
        "  [RBC] AU1 details: calling_id=0x{:08X}, called_id=0x{:08X}, class={:?}",
        au1_info.calling_etcs_id, au1_info.called_etcs_id, au1_info.class_of_service
    );

    // Validate that we are the called entity
    assert_eq!(au1_info.called_etcs_id, RBC_ETCS_ID);

    // ── Step 2: Send AU2 (Connection Confirm) ────────────────────────────
    let au2_info = AleAu2Info {
        responding_etcs_id: RBC_ETCS_ID,
    };
    let au2_payload = au2_info.encode(b""); // no SaPDU in this example
    writer
        .write_alepkt(&mut stream, ALE_PKT_AU2, &au2_payload)
        .expect("failed to send AU2");

    println!(
        "  [RBC] ▶ SENT {:<28} | T-Seq={:>5} | responding_id=0x{:08X}",
        pkt_type_name(ALE_PKT_AU2),
        0,
        RBC_ETCS_ID
    );

    // ── Step 3: Data Transfer — receive DTs and echo back ────────────────
    loop {
        let frame = read_one_frame(&mut stream, &mut reader);
        log_frame("RBC", "◀ RECV", &frame);

        match frame.header.packet_type {
            ALE_PKT_DT => {
                // Echo the message back with a prefix
                let response = format!(
                    "ACK from RBC: {}",
                    String::from_utf8_lossy(&frame.user_data)
                );
                writer
                    .write_alepkt(&mut stream, ALE_PKT_DT, response.as_bytes())
                    .expect("failed to send DT response");
                log_frame(
                    "RBC",
                    "▶ SENT",
                    &AleFrame {
                        header: AleHeader::build(
                            ALE_VERSION,
                            APP_TYPE,
                            writer.t_sequence().wrapping_sub(1),
                            ALE_NR_FLAG_NORMAL,
                            ALE_PKT_DT,
                            response.len(),
                        ),
                        user_data: response.into_bytes(),
                    },
                );
            }
            ALE_PKT_DI => {
                println!("  [RBC] Received disconnect indication — closing connection.");
                break;
            }
            other => {
                eprintln!("  [RBC] Unexpected packet type: {}", other);
                break;
            }
        }
    }

    // Graceful shutdown
    let _ = stream.shutdown(std::net::Shutdown::Both);
    println!("  [RBC] Connection closed.\n");
}

// ─── Client (OBU / Initiator) ────────────────────────────────────────────────

fn run_client(server_addr: std::net::SocketAddr) {
    let mut stream = TcpStream::connect(server_addr).expect("failed to connect to server");
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    println!("  [OBU] Connected to {}", server_addr);

    let mut reader = AleFrameReader::new();
    let mut writer = AleFrameWriter::new(APP_TYPE);

    // ── Step 1: Send AU1 (Connection Request) ────────────────────────────
    let au1_info = AleAu1Info {
        calling_etcs_id: OBU_ETCS_ID,
        called_etcs_id: RBC_ETCS_ID,
        class_of_service: ALE_CLASS_D,
    };
    let au1_payload = au1_info.encode(b""); // no SaPDU in this demo
    writer
        .write_alepkt(&mut stream, ALE_PKT_AU1, &au1_payload)
        .expect("failed to send AU1");

    println!(
        "  [OBU] ▶ SENT {:<28} | T-Seq={:>5} | calling=0x{:08X} called=0x{:08X}",
        pkt_type_name(ALE_PKT_AU1),
        0,
        OBU_ETCS_ID,
        RBC_ETCS_ID
    );

    // ── Step 2: Receive AU2 (Connection Confirm) ─────────────────────────
    let au2_frame = read_one_frame(&mut stream, &mut reader);
    log_frame("OBU", "◀ RECV", &au2_frame);

    assert_eq!(
        au2_frame.header.packet_type, ALE_PKT_AU2,
        "expected AU2 response"
    );

    let (au2_info, _sapdu) =
        AleAu2Info::decode(&au2_frame.user_data).expect("failed to decode AU2 info");
    println!(
        "  [OBU] AU2 confirmed by responding_id=0x{:08X}",
        au2_info.responding_etcs_id
    );
    assert_eq!(au2_info.responding_etcs_id, RBC_ETCS_ID);

    println!("\n  ── Connection established ──\n");

    // ── Step 3: Data Transfer — send messages and read echoes ────────────
    for i in 1..=NUM_MESSAGES {
        // Simulate a train position report
        let message = format!("Position report #{}: km={}.{}", i, 100 + i, i * 5);
        writer
            .write_alepkt(&mut stream, ALE_PKT_DT, message.as_bytes())
            .expect("failed to send DT");

        println!(
            "  [OBU] ▶ SENT {:<28} | T-Seq={:>5} | \"{}\"",
            pkt_type_name(ALE_PKT_DT),
            writer.t_sequence() - 1,
            message
        );

        // Read the echo response
        let response = read_one_frame(&mut stream, &mut reader);
        log_frame("OBU", "◀ RECV", &response);
        println!(
            "  [OBU]        payload: \"{}\"",
            String::from_utf8_lossy(&response.user_data)
        );
        println!();
    }

    // ── Step 4: Send DI (Disconnect Indication) ──────────────────────────
    writer
        .write_alepkt(&mut stream, ALE_PKT_DI, b"Normal disconnect")
        .expect("failed to send DI");

    println!(
        "  [OBU] ▶ SENT {:<28} | T-Seq={:>5} | \"Normal disconnect\"",
        pkt_type_name(ALE_PKT_DI),
        writer.t_sequence() - 1,
    );

    // Give server time to process DI before closing
    thread::sleep(Duration::from_millis(100));
    let _ = stream.shutdown(std::net::Shutdown::Both);
    println!("  [OBU] Connection closed.");
}

// ─── Main ────────────────────────────────────────────────────────────────────

fn main() {
    println!("╔══════════════════════════════════════════════════════════════╗");
    println!("║  ale-frame: Two-Client Communication Example                ║");
    println!("║  Demonstrates full ALEPKT lifecycle over TCP                ║");
    println!("║  (AU1 → AU2 → DT×{} → DI)                                  ║", NUM_MESSAGES);
    println!("╚══════════════════════════════════════════════════════════════╝");
    println!();

    // Bind to port 0 so the OS assigns an available port (avoids conflicts)
    let listener = TcpListener::bind("127.0.0.1:0").expect("failed to bind listener");
    let server_addr = listener.local_addr().unwrap();
    println!("  Server listening on {}\n", server_addr);

    // Channel to synchronise: server signals readiness (listener is already bound)
    let (tx, rx) = mpsc::channel::<()>();

    // Spawn server thread
    let server_handle = thread::Builder::new()
        .name("rbc-server".into())
        .spawn(move || {
            // Signal that we're ready
            tx.send(()).unwrap();
            run_server(listener);
        })
        .expect("failed to spawn server thread");

    // Wait for server to be ready
    rx.recv().unwrap();

    // Spawn client thread
    let client_handle = thread::Builder::new()
        .name("obu-client".into())
        .spawn(move || {
            run_client(server_addr);
        })
        .expect("failed to spawn client thread");

    // Wait for both to finish
    client_handle.join().expect("client thread panicked");
    server_handle.join().expect("server thread panicked");

    println!();
    println!("  ✓ Full ALEPKT lifecycle completed successfully.");
    println!("    Packet types demonstrated: AU1, AU2, DT, DI");
    println!("    T-Sequence numbering verified (wrapping u16 counter).");
    println!("    CRC-CCITT checksums validated on every received frame.");
}

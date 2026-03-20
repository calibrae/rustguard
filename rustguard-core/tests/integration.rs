//! Integration tests for the full WireGuard protocol flow.
//!
//! These test the complete path: handshake -> transport -> replay protection
//! without any network I/O — pure in-memory protocol verification.

use rustguard_core::handshake;
use rustguard_core::messages::{Initiation, Response, Transport, INITIATION_SIZE, RESPONSE_SIZE};
use rustguard_crypto::StaticSecret;

/// Helper: run a full handshake between two peers, return their sessions.
fn do_handshake() -> (
    rustguard_core::session::TransportSession,
    rustguard_core::session::TransportSession,
) {
    let init_static = StaticSecret::random();
    let resp_static = StaticSecret::random();
    let resp_public = resp_static.public_key();

    let (init_msg, init_state) = handshake::create_initiation(&init_static, &resp_public, 1);

    let (peer_key, _ts, resp_msg, resp_session) =
        handshake::process_initiation(&resp_static, &init_msg, 2)
            .expect("responder rejects initiation");

    assert_eq!(peer_key, init_static.public_key());

    let init_session = handshake::process_response(init_state, &init_static, &resp_msg)
        .expect("initiator rejects response");

    (init_session, resp_session)
}

#[test]
fn full_handshake_transport_roundtrip() {
    let (mut init, mut resp) = do_handshake();

    // Send 100 packets each direction.
    for i in 0u32..100 {
        let payload = format!("init->resp packet {i}");
        let (ctr, ct) = init.encrypt(payload.as_bytes()).unwrap();
        let pt = resp.decrypt(ctr, &ct).unwrap();
        assert_eq!(pt, payload.as_bytes());
    }

    for i in 0u32..100 {
        let payload = format!("resp->init packet {i}");
        let (ctr, ct) = resp.encrypt(payload.as_bytes()).unwrap();
        let pt = init.decrypt(ctr, &ct).unwrap();
        assert_eq!(pt, payload.as_bytes());
    }
}

#[test]
fn replay_attack_blocked() {
    let (mut init, mut resp) = do_handshake();

    let (ctr, ct) = init.encrypt(b"first").unwrap();
    assert!(resp.decrypt(ctr, &ct).is_some());

    // Replay the same packet — must be rejected.
    assert!(resp.decrypt(ctr, &ct).is_none());

    // Replay with different counter — AEAD will fail.
    assert!(resp.decrypt(ctr + 1, &ct).is_none());
}

#[test]
fn out_of_order_delivery() {
    let (mut init, mut resp) = do_handshake();

    // Encrypt 10 packets, deliver in reverse order.
    let packets: Vec<(u64, Vec<u8>, Vec<u8>)> = (0..10)
        .map(|i| {
            let payload = format!("packet {i}");
            let (ctr, ct) = init.encrypt(payload.as_bytes()).unwrap();
            (ctr, ct, payload.into_bytes())
        })
        .collect();

    for (ctr, ct, expected) in packets.iter().rev() {
        let pt = resp.decrypt(*ctr, ct).unwrap();
        assert_eq!(&pt, expected);
    }

    // Replaying any of them should fail now.
    for (ctr, ct, _) in &packets {
        assert!(resp.decrypt(*ctr, ct).is_none());
    }
}

#[test]
fn wire_format_roundtrip() {
    let init_static = StaticSecret::random();
    let resp_static = StaticSecret::random();
    let resp_public = resp_static.public_key();

    // Serialize/deserialize initiation.
    let (init_msg, _) = handshake::create_initiation(&init_static, &resp_public, 42);
    let wire = init_msg.to_bytes();
    assert_eq!(wire.len(), INITIATION_SIZE);
    let parsed = Initiation::from_bytes(&wire);
    assert_eq!(parsed.sender_index, 42);
    assert_eq!(parsed.ephemeral, init_msg.ephemeral);

    // Now do a real handshake and test transport wire format.
    let (init_msg, init_state) = handshake::create_initiation(&init_static, &resp_public, 1);
    let (_, _ts, resp_msg, mut resp_session) =
        handshake::process_initiation(&resp_static, &init_msg, 2).unwrap();

    let resp_wire = resp_msg.to_bytes();
    assert_eq!(resp_wire.len(), RESPONSE_SIZE);
    let parsed_resp = Response::from_bytes(&resp_wire);
    assert_eq!(parsed_resp.sender_index, 2);

    let mut init_session =
        handshake::process_response(init_state, &init_static, &resp_msg).unwrap();

    // Transport message.
    let (ctr, ct) = init_session.encrypt(b"test payload").unwrap();
    let transport = Transport {
        receiver_index: init_session.their_index,
        counter: ctr,
        payload: ct.clone(),
    };
    let transport_wire = transport.to_bytes();
    let parsed_transport = Transport::from_bytes(&transport_wire).unwrap();
    assert_eq!(parsed_transport.receiver_index, init_session.their_index);
    assert_eq!(parsed_transport.counter, ctr);
    assert_eq!(
        resp_session
            .decrypt(parsed_transport.counter, &parsed_transport.payload)
            .unwrap(),
        b"test payload"
    );
}

#[test]
fn multiple_independent_handshakes() {
    // Simulate a responder handling multiple initiators.
    let resp_static = StaticSecret::random();
    let resp_public = resp_static.public_key();

    let mut sessions = Vec::new();
    for i in 0..5u32 {
        let init_static = StaticSecret::random();
        let (init_msg, init_state) =
            handshake::create_initiation(&init_static, &resp_public, i + 100);

        let (_, _ts, resp_msg, resp_session) =
            handshake::process_initiation(&resp_static, &init_msg, i + 200)
                .expect("handshake failed");

        let init_session =
            handshake::process_response(init_state, &init_static, &resp_msg)
                .expect("response failed");

        sessions.push((init_session, resp_session));
    }

    // Each pair can communicate independently.
    for (i, (init, resp)) in sessions.iter_mut().enumerate() {
        let msg = format!("hello from peer {i}");
        let (ctr, ct) = init.encrypt(msg.as_bytes()).unwrap();
        let pt = resp.decrypt(ctr, &ct).unwrap();
        assert_eq!(String::from_utf8(pt).unwrap(), msg);
    }
}

#[test]
fn tampered_transport_rejected() {
    let (mut init, mut resp) = do_handshake();

    let (ctr, mut ct) = init.encrypt(b"sensitive data").unwrap();

    // Tamper with ciphertext.
    ct[0] ^= 0xff;
    assert!(resp.decrypt(ctr, &ct).is_none());
}

#[test]
fn empty_transport_packet() {
    // WireGuard uses empty transport packets as keepalives.
    let (mut init, mut resp) = do_handshake();

    let (ctr, ct) = init.encrypt(b"").unwrap();
    let pt = resp.decrypt(ctr, &ct).unwrap();
    assert!(pt.is_empty());
}

#[test]
fn max_size_transport_packet() {
    let (mut init, mut resp) = do_handshake();

    // MTU 1420 minus IP/UDP headers, this is roughly the max WireGuard payload.
    let payload = vec![0xAA; 1400];
    let (ctr, ct) = init.encrypt(&payload).unwrap();
    let pt = resp.decrypt(ctr, &ct).unwrap();
    assert_eq!(pt, payload);
}

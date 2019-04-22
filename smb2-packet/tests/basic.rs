#![warn(clippy::all)]
#![warn(clippy::pedantic)]
#![deny(clippy::correctness)]

#[allow(dead_code)]
mod common;

use smb2_packet::command::{Command, RequestBody, ResponseBody};
use smb2_packet::header::{Flags, Signature, SyncType};
use smb2_packet::Dialect;

use crate::common::{parse_pcap_requests, parse_pcap_responses};

#[test]
fn all_requests_just_parse() {
    let mut buffer = Vec::new();
    let requests = parse_pcap_requests("all_requests", &mut buffer).unwrap();
    let len = requests.len();
    let len_should = 801;
    assert!(
        len == len_should,
        "Length should be {} but is {}",
        len_should,
        len
    );
}

#[test]
fn all_responses_just_parse() {
    let mut buffer = Vec::new();
    let responses = parse_pcap_responses("all_responses", &mut buffer).unwrap();
    let len = responses.len();
    let len_should = 244;
    assert!(
        len == len_should,
        "Length should be {} but is {}",
        len_should,
        len
    );
}

#[test]
fn header1() {
    let mut buffer = Vec::new();
    let request = &parse_pcap_requests("header1", &mut buffer).unwrap()[0];
    let header = &request.header;

    assert_eq!(header.credit_charge, Some(0));
    assert_eq!(header.channel_sequence, Some(0));
    assert_eq!(header.credit_request, 52);
    assert_eq!(header.flags, Flags::empty());
    assert_eq!(header.message_id, 15);
    assert_eq!(header.sync_type, SyncType::Sync { tree_id: 5 });
    assert_eq!(header.session_id, 0x0000_0400_0000_0005);
    assert_eq!(header.signature, Signature::empty());

    match &request.body {
        RequestBody::NotImplemented { command, .. } => assert_eq!(*command, Command::QueryInfo),
        _ => panic!("Expected not implemented!"),
    };
}

#[test]
fn header2() {
    let mut buffer = Vec::new();
    let request = &parse_pcap_responses("header2", &mut buffer).unwrap()[0];
    let header = &request.header;

    assert_eq!(header.credit_charge, Some(0));
    assert_eq!(header.credit_response, 2);
    assert_eq!(header.flags, Flags::SERVER_TO_REDIR);
    assert_eq!(header.message_id, 34);
    assert_eq!(
        header.sync_type,
        SyncType::Sync {
            tree_id: 0x0c09_ef82
        }
    );
    assert_eq!(header.session_id, 0x0000_0000_2a16_df11);
    assert_eq!(header.signature, Signature::empty());

    match &request.body {
        ResponseBody::NotImplemented { command, .. } => assert_eq!(*command, Command::Read),
        _ => panic!("Expected not implemented!"),
    };
}

#[test]
fn negotiate_request() {
    use smb2_packet::command::negotiate::*;

    let mut buffer = Vec::new();
    let request = &parse_pcap_requests("negotiate_request", &mut buffer).unwrap()[0];
    let body;
    let client_guid = [
        0xa3, 0x09, 0x6f, 0x6d, 0x22, 0xc1, 0x53, 0x79, 0x9d, 0x99, 0x95, 0xf3, 0xb3, 0xd7, 0xb9,
        0x65,
    ];
    let dialects = [
        Dialect::Smb2_0_2,
        Dialect::Smb2_1_0,
        Dialect::Smb3_0_0,
        Dialect::Smb3_0_2,
    ];

    match &request.body {
        RequestBody::Negotiate(msg) => body = msg,
        _ => panic!("Expected not implemented!"),
    };

    assert_eq!(body.security_mode, SecurityMode::SigningEnabled);
    assert_eq!(
        body.capabilities,
        Capabilities::DFS
            | Capabilities::LEASING
            | Capabilities::LARGE_MTU
            | Capabilities::PERSISTENT_HANDLES
            | Capabilities::DIRECTORY_LEASING
            | Capabilities::ENCRYPTION
    );
    assert_eq!(body.client_guid, client_guid);
    assert_eq!(body.dialects, dialects);
    assert_eq!(body.negotiate_contexts.len(), 0);
}

#[test]
fn negotiate_with_context_request() {
    use smb2_packet::command::negotiate::*;

    let mut buffer = Vec::new();
    let request = &parse_pcap_requests("negotiate_with_context_request", &mut buffer).unwrap()[0];
    let body;
    let client_guid = [
        0xe8, 0xb8, 0x35, 0x76, 0xaa, 0x4f, 0x42, 0x58,
        0x8c, 0xa2, 0xc7, 0xaa, 0xce, 0xa9, 0xba, 0x80
    ];
    let dialects = [
        Dialect::Smb3_1_1,
    ];

    match &request.body {
        RequestBody::Negotiate(msg) => body = msg,
        _ => panic!("Expected not implemented!"),
    };

    assert_eq!(body.security_mode, SecurityMode::SigningEnabled);
    assert_eq!(
        body.capabilities,
        Capabilities::DFS
            | Capabilities::LEASING
            | Capabilities::LARGE_MTU
            | Capabilities::PERSISTENT_HANDLES
            | Capabilities::DIRECTORY_LEASING
            | Capabilities::ENCRYPTION
    );
    assert_eq!(body.client_guid, client_guid);
    assert_eq!(body.dialects, dialects);
    assert_eq!(body.negotiate_contexts.len(), 3);

    let preauth_ctx = if let Context::PreauthIntegrityCapabilities(x) = &body.negotiate_contexts[0] { x } else { panic!("first is preauth")};
    let enc_ctx = if let Context::EncryptionCapabilities(x) = &body.negotiate_contexts[0] { x } else { panic!("second is enc")};
    let unknown = if let Context::Unknown(x) = body.negotiate_contexts[0] { x } else { panic!("third is unknown")};
}

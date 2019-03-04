#![warn(clippy::all)]
#![warn(clippy::pedantic)]
#![deny(clippy::correctness)]

#[allow(dead_code)]
mod common;

use smb2_packet::command::{Command, RequestBody};
use smb2_packet::header::{Flags, Signature, SyncType};

use crate::common::parse_pcap_requests;

#[test]
fn all_requests_just_parse() {
    let mut buffer = Vec::new();
    let requests = parse_pcap_requests("all_Requests", &mut buffer).unwrap();
    let len = requests.len();
    let len_should = 789;
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

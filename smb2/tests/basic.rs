#![warn(clippy::all)]

mod common;

use smb2::command::{Command, RequestBody};
use smb2::header::SyncType;

use crate::common::parse_pcap;

#[test]
fn all_requests_just_parse() {
    let mut buffer = Vec::new();
    let requests = parse_pcap("all_Requests", &mut buffer).unwrap();
    let len = requests.len();
    let len_should = 791;
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
    let request = &parse_pcap("header1", &mut buffer).unwrap()[0];
    let request = request.unwrap_v2();
    let header = &request.header;

    assert_eq!(header.credit_charge, Some(0));
    assert_eq!(header.channel_sequence, Some(0));
    assert_eq!(header.credit_request, 52);
    assert_eq!(header.flags, smb2::header::Flags::empty());
    assert_eq!(header.message_id, 15);
    assert_eq!(header.sync_type, SyncType::Sync { tree_id: 5 });
    assert_eq!(header.session_id, 0x0000_0400_0000_0005);
    assert_eq!(header.signature, smb2::header::Signature::empty());

    match &request.body {
        RequestBody::NotImplemented { command, .. } => assert_eq!(*command, Command::QueryInfo),
        _ => panic!("Expected not implemented!"),
    };
}

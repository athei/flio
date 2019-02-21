#![warn(clippy::all)]

mod common;

use crate::common::parse_pcap;

#[test]
fn all_requests_just_parse() {
    let mut buffer = Vec::new();
    let requests = parse_pcap("all_Requests", &mut buffer).unwrap();
    let len = requests.len(); 
    let len_should = 791;
    assert!(len == len_should, "Length should be {} but is {}", len_should, len);
}

#[test]
fn header1() {
    let mut buffer = Vec::new();
    let request = &parse_pcap("header1", &mut buffer).unwrap()[0];
    let header = &request.unwrap_v2().header;

    assert_eq!(header.credit_charge, Some(0));
    assert_eq!(header.channel_sequence, Some(0));
    assert_eq!(header.status, None);
    assert_eq!(header.command, 16);
    assert_eq!(header.credit_req_grant, 52);
    assert_eq!(header.flags, smb2::header::Flags::empty());
    assert_eq!(header.message_id, 15);
    assert_eq!(header.async_id, None);
    assert_eq!(header.tree_id, Some(5));
    assert_eq!(header.session_id, 0x0000040000000005);
    assert_eq!(header.signature, [0; 16]);
}

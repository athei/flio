#![warn(clippy::all)]

mod common;

use crate::common::parse_pcap;

#[test]
fn first_smb1_request() {
    let mut buffer = Vec::new();
    let parsed = &parse_pcap("smb1_negot_requests", &mut buffer).unwrap().requests;

    let first;
    let second;

    if let common::CombinedRequest::V1(msg) = &parsed[0] {
        first = msg;
    } else {
        panic!("Should be a v1 message");
    }

    if let common::CombinedRequest::V1(msg) = &parsed[1] {
        second = msg;
    } else {
        panic!("Should be a v1 message");
    }

    assert_eq!(first.negotiate.level, smb2::V1Dialect::Smb2Plus);
    assert_eq!(second.negotiate.level, smb2::V1Dialect::NotSupported);
}

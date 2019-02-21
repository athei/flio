#![warn(clippy::all)]

mod common;

use crate::common::parse_pcap;

#[test]
fn smb1_negot_req_smb2plus() {
    let mut buffer = Vec::new();
    let req = &parse_pcap("smb1_negot_req_smb2plus", &mut buffer).unwrap()[0];
    let v1 = req.unwrap_v1();
    assert_eq!(v1.negotiate.level, smb2::V1Dialect::Smb2Plus);
}

#[test]
fn smb1_negot_req_not_supported() {
    let mut buffer = Vec::new();
    let req = &parse_pcap("smb1_negot_req_not_supported", &mut buffer).unwrap()[0];
    let v1 = req.unwrap_v1();
    assert_eq!(v1.negotiate.level, smb2::V1Dialect::NotSupported);
}

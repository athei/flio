#![warn(clippy::all)]
#![warn(clippy::pedantic)]
#![deny(clippy::correctness)]

#[allow(dead_code)]
mod common;

use crate::common::parse_pcap_smb1nego;
use smb2_packet::smb1::{DialectLevel, Flags, Flags2, Signature};

#[test]
fn smb1_negot_req_smb2plus() {
    let mut buffer = Vec::new();
    let req = &parse_pcap_smb1nego("smb1_negot_req_smb2plus", &mut buffer).unwrap()[0];
    assert_eq!(req.negotiate.level, DialectLevel::Smb2Plus);

    // check header
    let header = &req.header;
    assert_eq!(header.status, 0);
    assert_eq!(
        header.flags,
        Flags::CANONICALIZED_PATHS | Flags::CASE_INSENSITIVE
    );
    assert_eq!(
        header.flags2,
        Flags2::SMB_SECURITY_SIGNATURE_REQUIRED
            | Flags2::LONG_NAMES
            | Flags2::EAS
            | Flags2::EXTENDED_SECURITY
            | Flags2::UNICODE
            | Flags2::IS_LONG_NAME
            | Flags2::EXTENDED_SECURITY
            | Flags2::NT_STATUS
    );
    assert_eq!(header.tid, 65535);
    assert_eq!(header.pid, 65279);
    assert_eq!(header.uid, 0);
    assert_eq!(header.mid, 0);
    assert_eq!(header.signature, Signature::empty())
}

#[test]
fn smb1_negot_req_not_supported() {
    let mut buffer = Vec::new();
    let req = &parse_pcap_smb1nego("smb1_negot_req_not_supported", &mut buffer).unwrap()[0];
    assert_eq!(req.negotiate.level, DialectLevel::NotSupported);

    // check header
    let header = &req.header;
    assert_eq!(header.status, 0);
    assert_eq!(
        header.flags,
        Flags::CANONICALIZED_PATHS | Flags::CASE_INSENSITIVE
    );
    assert_eq!(
        header.flags2,
        Flags2::LONG_NAMES
            | Flags2::EAS
            | Flags2::EXTENDED_SECURITY
            | Flags2::UNICODE
            | Flags2::IS_LONG_NAME
            | Flags2::EXTENDED_SECURITY
            | Flags2::NT_STATUS
    );
    assert_eq!(header.tid, 0);
    assert_eq!(header.pid, 65279);
    assert_eq!(header.uid, 0);
    assert_eq!(header.mid, 0);
    assert_eq!(header.signature, Signature::empty())
}

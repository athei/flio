#![warn(clippy::all)]

mod common;

use crate::common::parse_pcap;
use smb2::smb1::{DialectLevel, Flags, Flags2};

#[test]
fn smb1_negot_req_smb2plus() {
    let mut buffer = Vec::new();
    let req = &parse_pcap("smb1_negot_req_smb2plus", &mut buffer).unwrap()[0];
    let v1 = req.unwrap_v1();
    assert_eq!(v1.negotiate.level, DialectLevel::Smb2Plus);

    // check header
    let header = &v1.header;
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
    assert_eq!(header.signature, [0; 8])
}

#[test]
fn smb1_negot_req_not_supported() {
    let mut buffer = Vec::new();
    let req = &parse_pcap("smb1_negot_req_not_supported", &mut buffer).unwrap()[0];
    let v1 = req.unwrap_v1();
    assert_eq!(v1.negotiate.level, DialectLevel::NotSupported);

    // check header
    let header = &v1.header;
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
    assert_eq!(header.signature, [0; 8])
}

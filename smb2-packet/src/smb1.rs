use bitflags::bitflags;
use nom::*;
use std::ops::Deref;

pub const SIG_SIZE: usize = 8;

bitflags! {
    pub struct Flags: u8 {
       const LOCK_AND_READ_OK = 0x01;
       const BUF_AVAIL = 0x02;
       const CASE_INSENSITIVE = 0x08;
       const CANONICALIZED_PATHS = 0x10;
       const OPLOCK = 0x20;
       const OPBATCH = 0x40;
       const REPLY = 0x80;
    }
}

bitflags! {
    pub struct Flags2: u16 {
        const LONG_NAMES = 0x01;
        const EAS = 0x02;
        const SMB_SECURITY_SIGNATURE = 0x04;
        const IS_LONG_NAME = 0x40;
        const DFS = 0x1000;
        const PAGING_IO = 0x2000;
        const NT_STATUS = 0x4000;
        const UNICODE = 0x8000;
        const COMPRESSED = 0x8;
        const SMB_SECURITY_SIGNATURE_REQUIRED = 0x10;
        const REPARSE_PATH = 0x400;
        const EXTENDED_SECURITY = 0x800;
    }
}

#[derive(PartialEq, Eq)]
#[cfg_attr(debug_assertions, derive(Debug))]
pub struct Signature([u8; SIG_SIZE]);

impl Signature {
    pub fn empty() -> Self {
        Self([0; SIG_SIZE])
    }
}

impl Deref for Signature {
    type Target = [u8; SIG_SIZE];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[derive(PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum DialectLevel {
    NotSupported,
    Smb2,
    Smb2Plus,
}

impl<'a> From<&'a [u8]> for DialectLevel {
    fn from(bytes: &'a [u8]) -> Self {
        match bytes {
            b"SMB 2.002" => DialectLevel::Smb2,
            b"SMB 2.???" => DialectLevel::Smb2Plus,
            _ => DialectLevel::NotSupported,
        }
    }
}

#[cfg_attr(debug_assertions, derive(Debug))]
pub struct Header {
    pub status: u32,
    pub flags: Flags,
    pub flags2: Flags2,
    pub tid: u16,
    pub pid: u32,
    pub uid: u16,
    pub mid: u16,
    pub signature: Signature,
}

#[cfg_attr(debug_assertions, derive(Debug))]
pub struct NegotiateRequest {
    pub header: Header,
    pub level: DialectLevel,
}

fn copy_sig(input: &[u8]) -> Signature {
    let mut ret = [0; SIG_SIZE];
    ret.copy_from_slice(input);
    Signature(ret)
}

fn merge_pid(high: u16, low: u16) -> u32 {
    (u32::from(high) << 16) + u32::from(low)
}

fn fold_dialect(accu: DialectLevel, add: &[u8]) -> DialectLevel {
    std::cmp::max(accu, add.into())
}

named!(
    extract_dialect,
    delimited!(tag!(b"\x02"), is_not!("b\x00"), tag!(b"\x00"))
);

fn parse_dialects(input: &[u8]) -> IResult<&[u8], DialectLevel> {
    fold_many1!(
        input,
        complete!(extract_dialect),
        DialectLevel::NotSupported,
        fold_dialect
    )
}

#[rustfmt::skip]
fn parse_header(input: &[u8]) -> IResult<&[u8], Header> {
    do_parse!(input,
        tag!(b"\xffSMB") >>
        tag!(b"\x72") >> /* negotiate command */
        status: le_u32 >>
        flags: map_opt!(le_u8, Flags::from_bits) >>
        verify!(value!(flags.contains(Flags::REPLY)), |is_reply: bool| !is_reply) >>
        flags2: map_opt!(le_u16, Flags2::from_bits) >>
        pid_high: le_u16 >>
        signature: map!(take!(SIG_SIZE), copy_sig) >>
        take!(2) >>
        tid: le_u16 >>
        pid_low: le_u16 >>
        uid: le_u16 >>
        mid: le_u16 >>
        (Header {
            status,
            flags,
            flags2,
            tid,
            pid: merge_pid(pid_high, pid_low),
            uid,
            mid,
            signature,
        })
    )
}

named!(
    parse_body<DialectLevel>,
    preceded!(tag!(b"\x00"), length_value!(le_u16, parse_dialects))
);

pub fn parse_negotiate(input: &[u8]) -> IResult<&[u8], NegotiateRequest> {
    do_parse!(
        input,
        header: parse_header >> level: parse_body >> (NegotiateRequest { header, level })
    )
}

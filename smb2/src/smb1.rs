use bitflags::bitflags;
use nom::*;

const SIG_SIZE: usize = 8;

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

pub struct Header {
    status: u32,
    flags: Flags,
    flags2: Flags2,
    tid: u16,
    pid: u32,
    uid: u16,
    mid: u16,
    signature: [u8; SIG_SIZE],
}

fn copy_sig(input: &[u8]) -> [u8; SIG_SIZE] {
    let mut ret = [0; SIG_SIZE];
    ret.copy_from_slice(input);
    ret
}

fn merge_pid(high: u16, low: u16) -> u32 {
    let b1: u8 = (high >> 8) as u8;
    let b2: u8 = (high & 0xff) as u8;
    let b3: u8 = (low >> 8) as u8;
    let b4: u8 = (low & 0xff) as u8;

    unsafe {
        std::mem::transmute([b1, b2, b3, b4])
    }
}

pub fn parse_request(input: &[u8]) -> IResult<&[u8], (Header, &[u8])> {
    do_parse!(input,
        verify!(le_u8, |v| v == 0xFF) >>
        tag!("SMB") >>
        command: le_u8 >>
        status: le_u32 >>
        flags: map_opt!(le_u8, Flags::from_bits) >>
        flags2: map_opt!(le_u16, Flags2::from_bits) >>
        pid_high: le_u16 >>
        signature: map!(take!(SIG_SIZE), copy_sig) >>
        take!(2) >>
        tid: le_u16 >>
        pid_low: le_u16 >>
        uid: le_u16 >>
        mid: le_u16 >>
        body: rest >>
        (Header {
            status,
            flags,
            flags2,
            tid,
            pid: merge_pid(pid_high, pid_low),
            uid,
            mid,
            signature
        }, body)
    )
}

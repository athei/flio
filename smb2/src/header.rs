use byteorder::{BigEndian, ByteOrder};
use bitflags::bitflags;
use ::Dialect;
use nom::*;

const SMB_HEADER_LEN: usize = 64;
const SIG_SIZE: usize = 16;

bitflags! {
    pub struct Flags: u32 {
        const SERVER_TO_REDIR = 0x1;
        const ASYNC_COMMAND = 0x2;
        const RELATED_OPERATIONS = 0x4;
        const SIGNED = 0x8;
        const PRIORITY_MASK = 0x70;
        const DFS_OPERATIONS = 0x10000000;
        const REPLAY_OPERATION = 0x20000000;
    }
}

#[derive(Debug)]
pub struct Header {
    pub credit_charge: Option<u16>,
    pub channel_sequence: Option<u16>,
    pub status: Option<u32>,
    pub command: u16,
    pub credit_req_grant: u16,
    pub flags: Flags,
    pub message_id: u64,
    pub async_id: Option<u64>,
    pub tree_id: Option<u32>,
    pub session_id: u64,
    pub signature: [u8; SIG_SIZE],
}

fn copy_sig(input: &[u8]) -> [u8; SIG_SIZE] {
    let mut ret = [0; SIG_SIZE];
    ret.copy_from_slice(input);
    ret
}

fn derive_channel_sequence(input: &[u8], dialect: Dialect, is_response: bool) -> Option<u16> {
    if is_response {
        return None
    }

    match dialect {
        Dialect::Smb3_0_0 | Dialect::Smb3_0_2 | Dialect::Smb3_1_1 => Some(BigEndian::read_u16(input)),
        _ => None
    }
}

fn derive_status(input: &[u8], dialect: Dialect, is_response: bool) -> Option<u32> {
    match dialect {
        Dialect::Smb2_0_2 | Dialect::Smb2_1_0 | _ if is_response => Some(BigEndian::read_u32(input)),
        _ => None
    }
}

pub fn parse(input: &[u8], dialect: Dialect, is_response: bool) -> IResult<&[u8], (Header, &[u8])> {
    do_parse!(input,
        tag!(b"\xfeSMB") >>
        verify!(le_u16, |v| v == SMB_HEADER_LEN as u16) >>
        credit_charge: cond!(dialect > Dialect::Smb2_0_2, le_u16) >>
        status: take!(4) >>
        command: le_u16 >>
        credit_req_grant: le_u16 >>
        flags: map_opt!(le_u32, Flags::from_bits) >>
        verify!(value!(flags.contains(Flags::SERVER_TO_REDIR)), |val| val == is_response) >>
        next_command: le_u32 >>
        message_id: le_u64 >>
        cond!(!flags.contains(Flags::ASYNC_COMMAND), take!(4)) >>
        tree_id: cond!(!flags.contains(Flags::ASYNC_COMMAND), le_u32) >>
        async_id: cond!(flags.contains(Flags::ASYNC_COMMAND), le_u64) >>
        session_id: le_u64 >>
        signature: map!(take!(SIG_SIZE), copy_sig) >>
        body: switch!(value!(next_command > SMB_HEADER_LEN as u32),
            true => take!(next_command - SMB_HEADER_LEN as u32) |
            false => take!(input.len() - SMB_HEADER_LEN)
        ) >>
        (Header {
            credit_charge,
            channel_sequence: derive_channel_sequence(status, dialect, is_response),
            status: derive_status(status, dialect, is_response),
            command,
            credit_req_grant,
            flags,
            message_id,
            async_id,
            tree_id,
            session_id,
            signature,
        }, body)
    )
}

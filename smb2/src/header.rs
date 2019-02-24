use bitflags::bitflags;
use byteorder::{ByteOrder, LittleEndian};
use nom::*;
use num_traits::FromPrimitive;

use crate::command::Command;
use crate::Dialect;

pub const HEADER_LEN: usize = 64;
pub const SIG_SIZE: usize = 16;

bitflags! {
    pub struct Flags: u32 {
        const SERVER_TO_REDIR = 0x1;
        const ASYNC_COMMAND = 0x2;
        const RELATED_OPERATIONS = 0x4;
        const SIGNED = 0x8;
        const PRIORITY_MASK = 0x70;
        const DFS_OPERATIONS = 0x1000_0000;
        const REPLAY_OPERATION = 0x2000_0000;
    }
}

#[derive(Debug, PartialEq)]
pub enum SyncType {
    Async { async_id: u64 },
    Sync { tree_id: u32 },
}

pub trait Header
where
    Self: Sized,
{
    const IS_RESPONSE: bool;

    #[allow(clippy::too_many_arguments)]
    fn new(
        credit_charge: Option<u16>,
        credit_req_resp: u16,
        channel_sequence: Option<u16>,
        status: Option<u32>,
        flags: Flags,
        message_id: u64,
        sync_type: SyncType,
        session_id: u64,
        signature: [u8; SIG_SIZE],
    ) -> Self;

    fn get_status(&self) -> Option<u32>;

    #[allow(clippy::cyclomatic_complexity)]
    #[rustfmt::skip]
    fn parse<'a>(input: &'a [u8], dialect: Dialect) -> IResult<&'a [u8], ParseResult<Self>>
    {
        do_parse!(input,
            tag!(b"\xfeSMB") >>
            verify!(le_u16, |v| v == HEADER_LEN as u16) >>
            credit_charge: cond!(dialect > Dialect::Smb2_0_2, le_u16) >>
            status: take!(4) >>
            command: map_opt!(le_u16, FromPrimitive::from_u16) >>
            credit_req_grant: le_u16 >>
            flags: map_opt!(le_u32, Flags::from_bits) >>
            verify!(value!(flags.contains(Flags::SERVER_TO_REDIR)), |val| val == Self::IS_RESPONSE) >>
            next_command: le_u32 >>
            message_id: le_u64 >>
            cond!(!flags.contains(Flags::ASYNC_COMMAND), take!(4)) >>
            tree_id: cond!(!flags.contains(Flags::ASYNC_COMMAND), le_u32) >>
            async_id: cond!(flags.contains(Flags::ASYNC_COMMAND), le_u64) >>
            session_id: le_u64 >>
            signature: map!(take!(SIG_SIZE), copy_sig) >>
            body: switch!(value!(next_command > HEADER_LEN as u32),
                true => take!(next_command - HEADER_LEN as u32) |
                false => call!(rest)
            ) >>
            (
                ParseResult::<Self>::new( Self::new (
                        credit_charge,
                        credit_req_grant,
                        derive_channel_sequence(status, dialect, Self::IS_RESPONSE),
                        derive_status(status, dialect, Self::IS_RESPONSE),
                        flags,
                        message_id,
                        {
                            if let Some(tree_id) = tree_id {
                                SyncType::Sync { tree_id }
                            } else {
                                SyncType::Async { async_id: async_id.unwrap() }
                            }
                        },
                        session_id,
                        signature,
                    ),
                    command,
                    body
                )
            )
        )
    }
}

#[derive(Debug)]
pub struct RequestHeader {
    pub credit_charge: Option<u16>,
    pub credit_request: u16,
    pub channel_sequence: Option<u16>,
    pub flags: Flags,
    pub message_id: u64,
    pub sync_type: SyncType,
    pub session_id: u64,
    pub signature: [u8; SIG_SIZE],
}

#[derive(Debug)]
pub struct ResponseHeader {
    pub credit_charge: Option<u16>,
    pub credit_response: u16,
    pub status: u32,
    pub flags: Flags,
    pub message_id: u64,
    pub sync_type: SyncType,
    pub session_id: u64,
    pub signature: [u8; SIG_SIZE],
}

pub struct ParseResult<'a, T>
where
    T: Header,
{
    pub header: T,
    pub command: Command,
    pub body: &'a [u8],
}

impl Header for RequestHeader {
    const IS_RESPONSE: bool = false;

    fn new(
        credit_charge: Option<u16>,
        credit_req_resp: u16,
        channel_sequence: Option<u16>,
        _status: Option<u32>,
        flags: Flags,
        message_id: u64,
        sync_type: SyncType,
        session_id: u64,
        signature: [u8; SIG_SIZE],
    ) -> Self {
        RequestHeader {
            credit_charge,
            credit_request: credit_req_resp,
            channel_sequence,
            flags,
            message_id,
            sync_type,
            session_id,
            signature,
        }
    }

    fn get_status(&self) -> Option<u32> {
        None
    }
}

impl Header for ResponseHeader {
    const IS_RESPONSE: bool = true;

    fn new(
        credit_charge: Option<u16>,
        credit_req_resp: u16,
        _channel_sequence: Option<u16>,
        status: Option<u32>,
        flags: Flags,
        message_id: u64,
        sync_type: SyncType,
        session_id: u64,
        signature: [u8; SIG_SIZE],
    ) -> Self {
        ResponseHeader {
            credit_charge,
            credit_response: credit_req_resp,
            status: status.unwrap(),
            flags,
            message_id,
            sync_type,
            session_id,
            signature,
        }
    }

    fn get_status(&self) -> Option<u32> {
        Some(self.status)
    }
}

impl<'a, T> ParseResult<'a, T>
where
    T: Header,
{
    fn new(header: T, command: Command, body: &'a [u8]) -> Self {
        ParseResult {
            header,
            command,
            body,
        }
    }
}

fn copy_sig(input: &[u8]) -> [u8; SIG_SIZE] {
    let mut ret = [0; SIG_SIZE];
    ret.copy_from_slice(input);
    ret
}

fn derive_channel_sequence(input: &[u8], dialect: Dialect, is_response: bool) -> Option<u16> {
    if is_response {
        return None;
    }

    match dialect {
        Dialect::Smb3_0_0 | Dialect::Smb3_0_2 | Dialect::Smb3_1_1 => {
            Some(LittleEndian::read_u16(input))
        }
        _ => None,
    }
}

fn derive_status(input: &[u8], dialect: Dialect, is_response: bool) -> Option<u32> {
    match dialect {
        Dialect::Smb2_0_2 | Dialect::Smb2_1_0 | _ if is_response => {
            Some(LittleEndian::read_u32(input))
        }
        _ => None,
    }
}

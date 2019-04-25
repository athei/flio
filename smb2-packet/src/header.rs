use bitflags::bitflags;
use nom::*;
use num_derive::FromPrimitive;
use num_traits::FromPrimitive;
use std::ops::Deref;

use crate::ntstatus::NTStatus;
use crate::Dialect;

pub const STRUCTURE_SIZE: u16 = 64;
pub const SIG_SIZE: usize = 16;

#[cfg_attr(debug_assertions, derive(Debug))]
pub struct Request {
    pub credit_charge: Option<u16>,
    pub credit_request: u16,
    pub channel_sequence: Option<u16>,
    pub flags: Flags,
    pub message_id: u64,
    pub sync_type: SyncType,
    pub session_id: u64,
    pub signature: Signature,
}

#[cfg_attr(debug_assertions, derive(Debug))]
pub struct Response {
    pub credit_charge: Option<u16>,
    pub credit_response: u16,
    pub status: NTStatus,
    pub flags: Flags,
    pub message_id: u64,
    pub sync_type: SyncType,
    pub session_id: u64,
    pub signature: Signature,
}


#[repr(u16)]
#[derive(FromPrimitive, PartialEq, Eq)]
#[cfg_attr(debug_assertions, derive(Debug))]
pub enum Command {
    Negotiate = 0x00,
    SessionSetup = 0x01,
    Logoff = 0x02,
    TreeConnect = 0x03,
    TreeDisconnect = 0x04,
    Create = 0x05,
    Close = 0x06,
    Flush = 0x07,
    Read = 0x08,
    Write = 0x09,
    Lock = 0x0A,
    Ioctl = 0x0B,
    Cancel = 0x0C,
    Echo = 0x0D,
    QueryDirectory = 0x0E,
    ChangeNotify = 0x0F,
    QueryInfo = 0x10,
    SetInfo = 0x11,
    OplockBreak = 0x12,
}

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

#[derive(PartialEq, Eq)]
#[cfg_attr(debug_assertions, derive(Debug))]
pub enum SyncType {
    Async { async_id: u64 },
    Sync { tree_id: u32 },
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
        status: Option<NTStatus>,
        flags: Flags,
        message_id: u64,
        sync_type: SyncType,
        session_id: u64,
        signature: Signature,
    ) -> Self;

    fn get_status(&self) -> Option<NTStatus>;

    #[allow(clippy::cyclomatic_complexity)]
    #[rustfmt::skip]
    fn parse<'a>(input: &'a [u8], dialect: Dialect) -> IResult<&'a [u8], ParseResult<Self>>
    {
        do_parse!(input,
            tag!(b"\xfeSMB") >>
            verify!(le_u16, |v| v == STRUCTURE_SIZE) >>
            credit_charge: le_u16 >>
            status_bytes: take!(4) >>
            command: map_opt!(le_u16, FromPrimitive::from_u16) >>
            credit_req_grant: le_u16 >>
            flags: map_opt!(le_u32, Flags::from_bits) >>
            verify!(
                value!(flags.contains(Flags::SERVER_TO_REDIR)),
                |val| val == Self::IS_RESPONSE
            ) >>
            status: cond_with_error!(
                Self::IS_RESPONSE,
                map_opt!(
                    value!(value(le_u32, status_bytes)),
                    FromPrimitive::from_u32
                )
            ) >>
            channel_sequence: cond_with_error!(
                has_channel_sequence(dialect, Self::IS_RESPONSE),
                value!(value(le_u16, status_bytes))
            ) >>
            next_command: le_u32 >>
            message_id: le_u64 >>
            cond_with_error!(!flags.contains(Flags::ASYNC_COMMAND), take!(4)) >>
            tree_id: cond_with_error!(!flags.contains(Flags::ASYNC_COMMAND), le_u32) >>
            async_id: cond_with_error!(flags.contains(Flags::ASYNC_COMMAND), le_u64) >>
            session_id: le_u64 >>
            signature: map!(take!(SIG_SIZE), copy_sig) >>
            body: switch!(value!(next_command > u32::from(STRUCTURE_SIZE)),
                true => take!(next_command - u32::from(STRUCTURE_SIZE)) |
                false => call!(rest)
            ) >>
            (
                ParseResult::<Self>::new( Self::new (
                        if dialect > Dialect::Smb2_0_2 { Some(credit_charge) } else { None },
                        credit_req_grant,
                        channel_sequence,
                        status,
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

pub struct ParseResult<'a, T>
where
    T: Header,
{
    pub header: T,
    pub command: Command,
    pub body: &'a [u8],
}

impl Header for Request {
    const IS_RESPONSE: bool = false;

    fn new(
        credit_charge: Option<u16>,
        credit_req_resp: u16,
        channel_sequence: Option<u16>,
        _status: Option<NTStatus>,
        flags: Flags,
        message_id: u64,
        sync_type: SyncType,
        session_id: u64,
        signature: Signature,
    ) -> Self {
        Self {
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

    fn get_status(&self) -> Option<NTStatus> {
        None
    }
}

impl Header for Response {
    const IS_RESPONSE: bool = true;

    fn new(
        credit_charge: Option<u16>,
        credit_req_resp: u16,
        _channel_sequence: Option<u16>,
        status: Option<NTStatus>,
        flags: Flags,
        message_id: u64,
        sync_type: SyncType,
        session_id: u64,
        signature: Signature,
    ) -> Self {
        Self {
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

    fn get_status(&self) -> Option<NTStatus> {
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

fn copy_sig(input: &[u8]) -> Signature {
    let mut ret = [0; SIG_SIZE];
    ret.copy_from_slice(input);
    Signature(ret)
}

fn has_channel_sequence(dialect: Dialect, is_response: bool) -> bool {
    if is_response {
        return false;
    }

    match dialect {
        Dialect::Smb3_0_0 | Dialect::Smb3_0_2 | Dialect::Smb3_1_1 => true,
        _ => false,
    }
}

fn value<F, O>(f: F, data: &[u8]) -> O
where
    F: Fn(&[u8]) -> IResult<&[u8], O>,
{
    f(data).unwrap().1
}

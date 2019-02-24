#![warn(clippy::all)]

mod transport;

pub mod command;
pub mod smb1;
pub mod error;

use bitflags::bitflags;
use byteorder::{LittleEndian, ByteOrder};
use nom::*;
use num_traits::FromPrimitive;

pub const HEADER_LEN: usize = 64;
pub const SIG_SIZE: usize = 16;

#[derive(Clone, Copy, PartialEq, PartialOrd)]
pub enum Dialect {
    Smb2_0_2 = 0x0202,
    Smb2_1_0 = 0x0210,
    Smb3_0_0 = 0x0300,
    Smb3_0_2 = 0x0302,
    Smb3_1_1 = 0x0311,
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

#[derive(Debug, PartialEq)]
pub enum SyncType {
    Async { async_id: u64 },
    Sync { tree_id: u32 },
}

#[derive(Debug)]
pub struct Request<'a> {
    pub header: Header,
    pub command: command::Command,
    pub body: &'a [u8],
}

#[derive(Debug)]
pub struct Response<'a> {
    pub header: Header,
    pub body: Result<(command::Command, &'a [u8]), error::ErrorResponse>
}

#[derive(Debug)]
pub struct Header {
    pub credit_charge: Option<u16>,
    pub channel_sequence: Option<u16>,
    pub status: Option<u32>,
    pub credit_req_grant: u16,
    pub flags: Flags,
    pub message_id: u64,
    pub sync_type: SyncType,
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

#[allow(clippy::cyclomatic_complexity)]
#[rustfmt::skip]
fn parse(input: &[u8], dialect: Dialect, is_response: bool) -> IResult<&[u8], Request> {
    do_parse!(input,
        tag!(b"\xfeSMB") >>
        verify!(le_u16, |v| v == HEADER_LEN as u16) >>
        credit_charge: cond!(dialect > Dialect::Smb2_0_2, le_u16) >>
        status: take!(4) >>
        command: map_opt!(le_u16, FromPrimitive::from_u16) >>
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
        body: switch!(value!(next_command > HEADER_LEN as u32),
            true => take!(next_command - HEADER_LEN as u32) |
            false => call!(rest)
        ) >>
        ( Request {
            header: Header {
                credit_charge,
                channel_sequence: derive_channel_sequence(status, dialect, is_response),
                status: derive_status(status, dialect, is_response),
                credit_req_grant,
                flags,
                message_id,
                sync_type: {
                    if let Some(tree_id) = tree_id {
                        SyncType::Sync { tree_id }
                    } else {
                        SyncType::Async { async_id: async_id.unwrap() }
                    }
                },
                session_id,
                signature,
            },
            command,
            body
        })
    )
}

pub fn parse_request_complete(
    input: &[u8],
    dialect: Dialect,
) -> Result<Vec<Request>, nom::Err<&[u8]>> {
    let mut result = Vec::new();
    let mut cur = input;
    loop {
        match complete!(cur, apply!(parse, dialect, false)) {
            Ok((remainder, output)) => {
                result.push(output);
                if remainder.is_empty() {
                    break;
                }
                cur = remainder;
            }
            Err(x) => return Err(x),
        }
    }
    Ok(result)
}

pub fn parse_request(input: &[u8], dialect: Dialect) -> IResult<&[u8], Vec<Request>> {
    match transport::get_payload(input) {
        Ok((rem, out)) => parse_request_complete(out, dialect).map(|i| (rem, i)),
        Err(x) => Err(x),
    }
}

pub fn parse_smb1_nego_request_complete(input: &[u8]) -> Result<smb1::Request, nom::Err<&[u8]>> {
    match complete!(input, smb1::parse_negotiate) {
        Ok((rem, out)) => {
            assert!(
                rem.is_empty(),
                "Only pass complete segments into this function"
            );
            Ok(out)
        }
        Err(x) => Err(x),
    }
}

pub fn parse_smb1_nego_request(input: &[u8]) -> IResult<&[u8], smb1::Request> {
    match transport::get_payload(input) {
        Ok((rem, out)) => parse_smb1_nego_request_complete(out).map(|i| (rem, i)),
        Err(x) => Err(x),
    }
}

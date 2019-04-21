use crate::header::HEADER_LEN;
use crate::Dialect;
use bitflags::bitflags;
use nom::*;
use num_derive::FromPrimitive;
use num_traits::FromPrimitive;

const REQUEST_STRUCTURE_SIZE: u16 = 36;

#[repr(u16)]
#[derive(FromPrimitive, Eq, PartialEq)]
#[cfg_attr(debug_assertions, derive(Debug))]
pub enum SecurityMode {
    SigningEnabled = 0x01,
    SigningRequired = 0x02,
}

bitflags! {
    pub struct Capabilities: u32 {
        const DFS = 0x01;
        const LEASING = 0x02;
        const LARGE_MTU = 0x04;
        const MULTI_CHANNEL = 0x08;
        const PERSISTENT_HANDLES = 0x10;
        const DIRECTORY_LEASING = 0x20;
        const ENCRYPTION = 0x40;
    }
}

#[cfg_attr(debug_assertions, derive(Debug))]
pub enum Context<'a> {
    PreauthIntegrityCapabilities(&'a [u8]),
    EncryptionCapabilities(&'a [u8]),
}

impl<'a> Context<'a> {
    fn new(ctype: u16, data: &'a [u8]) -> Option<Self> {
        match ctype {
            0x01 => Some(Context::PreauthIntegrityCapabilities(data)),
            0x02 => Some(Context::EncryptionCapabilities(data)),
            _ => None,
        }
    }
}

#[cfg_attr(debug_assertions, derive(Debug))]
pub struct Request<'a> {
    pub security_mode: SecurityMode,
    pub capabilities: Capabilities,
    pub client_guid: &'a [u8],
    pub dialects: Vec<crate::Dialect>,
    pub negotiate_contexts: Vec<Context<'a>>,
}

#[cfg_attr(debug_assertions, derive(Debug))]
pub struct Response {}

fn parse_negotiate_context(input: &[u8]) -> IResult<&[u8], Option<Context>> {
    do_parse!(
        input,
        context_type: le_u16 >>
        data_length: le_u16 >>
        take!(8) >> /* reserved */
        data: take!(data_length) >>
        (Context::new(context_type, data))
    )
}

fn parse_negotiate_contexts(input: &[u8], packet_length: u16, offset: u32, count: u16) -> IResult<&[u8], Vec<Context>> {
    do_parse!(
        input,
        take!(offset - u32::from(packet_length)) >> /* optional padding */
        context: count!(map_opt!(parse_negotiate_context, |x| x), usize::from(count)) >>
        (context)
    )
}

#[allow(clippy::cyclomatic_complexity)]
pub fn parse<'a>(data: &'a [u8]) -> nom::IResult<&'a [u8], Request> {
    do_parse!(
        data,
        verify!(le_u16, |x| x == REQUEST_STRUCTURE_SIZE) >>
        dialect_count: verify!(le_u16, |x| x > 0) >>
        security_mode: map_opt!(le_u16, FromPrimitive::from_u16) >>
        take!(2) >> /* reserved */
        capabilities: map_opt!(le_u32, Capabilities::from_bits) >>
        client_guid: take!(16) >>
        negot_context_offset: le_u32 >>
        negot_context_count: le_u16 >>
        take!(2) >> /* reserved */
        dialects: count!(map_opt!(le_u16, FromPrimitive::from_u16), usize::from(dialect_count)) >>
        packet_length: value!(HEADER_LEN + REQUEST_STRUCTURE_SIZE + dialect_count * 2) >> /* length of the packet without contexts */
        negotiate_contexts: cond!(dialects.contains(&Dialect::Smb3_1_1), apply!(parse_negotiate_contexts, packet_length, negot_context_offset, negot_context_count)) >>
        (Request {
            security_mode,
            capabilities,
            client_guid,
            dialects,
            negotiate_contexts: negotiate_contexts.unwrap_or_default(),
        })
    )
}

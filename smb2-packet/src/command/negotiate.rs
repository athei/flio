use crate::header::HEADER_LEN;
use crate::Dialect;
use bitflags::bitflags;
use nom::*;
use num_derive::FromPrimitive;
use num_traits::FromPrimitive;
use std::convert::TryFrom;

const REQUEST_STRUCTURE_SIZE: u16 = 36;

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

#[repr(u16)]
#[cfg_attr(debug_assertions, derive(Debug))]
#[derive(FromPrimitive, PartialEq, Eq)]
pub enum HashAlgorithm {
    Sha512 = 0x01,
}

#[repr(u16)]
#[cfg_attr(debug_assertions, derive(Debug))]
#[derive(FromPrimitive, PartialEq, Eq)]
pub enum Cipher {
    Aes128Ccm = 0x01,
    Aes128Gcm = 0x02,
}

#[cfg_attr(debug_assertions, derive(Debug))]
pub struct PreauthIntegrityCapabilities<'a> {
    pub hash_algorithms: Vec<HashAlgorithm>,
    pub salt: &'a [u8],
}

#[cfg_attr(debug_assertions, derive(Debug))]
pub enum Context<'a> {
    PreauthIntegrityCapabilities(PreauthIntegrityCapabilities<'a>),
    EncryptionCapabilities(Vec<Cipher>),
    Unknown(&'a [u8]),
}

impl<'a> Context<'a> {
    #[rustfmt::skip]
    fn new(data: &'a [u8], ctype: u16) -> IResult<&[u8], Context> {
        match ctype {
            0x01 => do_parse!(data,
                algo_count: le_u16 >>
                salt_length: le_u16 >>
                hash_algorithms:
                    count!(
                        map_opt!(le_u16, FromPrimitive::from_u16),
                        usize::from(algo_count)
                    ) >>
                salt: take!(salt_length) >>
                (Context::PreauthIntegrityCapabilities(PreauthIntegrityCapabilities {
                        hash_algorithms,
                        salt,
                }))
            ),
            0x02 => do_parse!(data,
                cipher_count: le_u16 >>
                ciphers:
                    count!(
                        map_opt!(le_u16, FromPrimitive::from_u16),
                        usize::from(cipher_count)
                    ) >>
                (Context::EncryptionCapabilities(ciphers))
            ),
            _ => map!(data, rest, |d| Context::Unknown(d)),
        }
    }
}

#[rustfmt::skip]
fn parse_negotiate_context(input: &[u8], packet_len: u32) -> IResult<&[u8], Context> {
    // pad to the next 8 byte aligned packet offset
    let padding = (8 - ((packet_len - u32::try_from(input.len()).unwrap()) % 8)) % 8;
    do_parse!(input,
        take!(padding) >>
        context_type: le_u16 >>
        data_length: le_u16 >>
        take!(4) >> /* reserved */
        context: length_value!(value!(data_length), apply!(Context::new, context_type)) >>
        (context)
    )
}

#[rustfmt::skip]
fn parse_negotiate_contexts(
    input: &[u8],
    packet_length: u32,
    offset: u32,
    count: u16,
) -> IResult<&[u8], Vec<Context>> {
    let current_pos = packet_length - u32::try_from(input.len()).unwrap();
    let negot = do_parse!(input,
        verify!(value!(offset), |x| x >= current_pos) >>
        take!(offset - current_pos) >> /* optional padding */
        context: count!(apply!(parse_negotiate_context, packet_length), usize::from(count)) >>
        (context)
    );
    negot
}

#[rustfmt::skip]
#[allow(clippy::cyclomatic_complexity)]
pub fn parse<'a>(data: &'a [u8]) -> nom::IResult<&'a [u8], Request> {
    let packet_length = u32::try_from(data.len()).unwrap() + u32::from(HEADER_LEN);
    do_parse!(data,
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
        negotiate_contexts:
            cond_with_error!(
                dialects.contains(&Dialect::Smb3_1_1),
                apply!(
                    parse_negotiate_contexts,
                    packet_length,
                    negot_context_offset,
                    negot_context_count
                )
            ) >>
        (Request {
            security_mode,
            capabilities,
            client_guid,
            dialects,
            negotiate_contexts: negotiate_contexts.unwrap_or_default(),
        })
    )
}

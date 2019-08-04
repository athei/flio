use crate::{ClientGuid, Dialect, wrap};
use bitflags::bitflags;
use num_derive::FromPrimitive;
use num_traits::FromPrimitive;
use nom::{
    *, number::complete::{le_u16, le_u32},
    combinator::rest,
};
use crate::IResult;

const REQUEST_STRUCTURE_SIZE: u16 = 36;

#[cfg_attr(debug_assertions, derive(Debug))]
pub struct Request<'a> {
    pub signing_required: bool,
    pub capabilities: Capabilities,
    pub client_guid: ClientGuid,
    pub dialects: Vec<crate::Dialect>,
    pub negotiate_contexts: Vec<Context<'a>>,
}

#[cfg_attr(debug_assertions, derive(Debug))]
pub struct Response<'a> {
    pub signing_required: bool,
    pub dialect: Dialect,
    pub server_guid: ClientGuid,
    pub capabilities: Capabilities,
    pub max_transact_size: u32,
    pub max_read_size: u32,
    pub system_time: std::time::SystemTime,
    pub server_start_time: std::time::SystemTime,
    pub security_buffer: Option<&'a [u8]>,
    pub negotiate_contexts: Vec<Context<'a>>,
}

bitflags! {
    pub struct Capabilities: u8 {
        const DFS = 0x01;
        const LEASING = 0x02;
        const LARGE_MTU = 0x04;
        const MULTI_CHANNEL = 0x08;
        const PERSISTENT_HANDLES = 0x10;
        const DIRECTORY_LEASING = 0x20;
        const ENCRYPTION = 0x40;
    }
}

#[repr(u8)]
#[cfg_attr(debug_assertions, derive(Debug))]
#[derive(FromPrimitive, PartialEq, Eq)]
pub enum HashAlgorithm {
    Sha512 = 0x01,
}

#[repr(u8)]
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
#[allow(clippy::cast_possible_truncation)]
fn parse_negotiate_context(input: &[u8], packet_len: u32) -> IResult<&[u8], Context> {
    // pad to the next 8 byte aligned packet offset
    let padding = (8 - ((packet_len - input.len() as u32) % 8)) % 8;
    do_parse!(input,
        take!(padding) >>
        context_type: le_u16 >>
        data_length: le_u16 >>
        take!(4) >> /* reserved */
        context: length_value!(wrap(data_length), call!(Context::new, context_type)) >>
        (context)
    )
}

#[rustfmt::skip]
#[allow(clippy::cast_possible_truncation)]
fn parse_negotiate_contexts(
    input: &[u8],
    packet_length: u32,
    offset: u32,
    count: u16,
) -> IResult<&[u8], Vec<Context>> {
    let current_pos = packet_length - input.len() as u32;
    let negot = do_parse!(input,
        verify!(wrap(offset), |&x| x >= current_pos) >>
        take!(offset - current_pos) >> /* optional padding */
        context: count!(call!(parse_negotiate_context, packet_length), usize::from(count)) >>
        (context)
    );
    negot
}

#[rustfmt::skip]
#[allow(clippy::cognitive_complexity)]
#[allow(clippy::cast_possible_truncation)]
pub fn parse<'a>(data: &'a [u8]) -> IResult<&'a [u8], Request> {
    let packet_length = data.len() as u32 + u32::from(crate::header::STRUCTURE_SIZE);
    do_parse!(data,
        verify!(le_u16, |&x| x == REQUEST_STRUCTURE_SIZE) >>
        dialect_count: verify!(le_u16, |&x| x > 0) >>
        security_mode: le_u16 >>
        take!(2) >> /* reserved */
        capabilities: map_opt!(le_u32, |x| Capabilities::from_bits(x as u8)) >>
        client_guid: map!(take!(16), ClientGuid::from_slice) >>
        negot_context_offset: le_u32 >>
        negot_context_count: le_u16 >>
        take!(2) >> /* reserved */
        dialects: count!(map_opt!(le_u16, FromPrimitive::from_u16), usize::from(dialect_count)) >>
        negotiate_contexts:
            cond!(
                dialects.contains(&Dialect::Smb3_1_1),
                call!(
                    parse_negotiate_contexts,
                    packet_length,
                    negot_context_offset,
                    negot_context_count
                )
            ) >>
        (Request {
            signing_required: (security_mode & 0x02) != 0,
            capabilities,
            client_guid,
            dialects,
            negotiate_contexts: negotiate_contexts.unwrap_or_default(),
        })
    )
}

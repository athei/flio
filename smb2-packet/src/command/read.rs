use crate::{Dialect, FileId};
use bitflags::bitflags;
use nom::*;
use num_derive::FromPrimitive;
use num_traits::FromPrimitive;

const REQUEST_STRUCTURE_SIZE: u16 = 49;
const REQUEST_CONSTANT_SIZE: u16 = crate::header::STRUCTURE_SIZE + REQUEST_STRUCTURE_SIZE - 1;

#[cfg_attr(debug_assertions, derive(Debug))]
pub struct Request<'a> {
    pub padding: u8,
    pub read_unbuffered: bool,
    pub length: u32,
    pub offset: u64,
    pub file_id: FileId,
    pub minimum_count: u32,
    pub remaining_bytes: u32,
    pub channel: Channel<'a>,
}

#[cfg_attr(debug_assertions, derive(Debug))]
pub struct Response<'a> {
    pub data_remaining: u32,
    pub data: &'a [u8],
}

bitflags! {
    struct Flags: u8 {
        const READ_UNBUFFERED = 0x01;
    }
}

#[repr(u8)]
#[cfg_attr(debug_assertions, derive(Debug))]
#[derive(FromPrimitive, PartialEq, Eq, Clone, Copy)]
enum ChannelType {
    None = 0x00,
    RdmaV1 = 0x01,
    RdmaV1Invalidate = 0x02,
}

#[cfg_attr(debug_assertions, derive(Debug))]
pub enum Channel<'a> {
    None,
    RdmaV1(&'a [u8]),
    RdmaV1Invalidate(&'a [u8]),
}

fn create_channel(buffer: &[u8], channel_type: ChannelType) -> Channel<'_> {
    match channel_type {
        ChannelType::None => Channel::None,
        ChannelType::RdmaV1 => Channel::RdmaV1(buffer),
        ChannelType::RdmaV1Invalidate => Channel::RdmaV1Invalidate(buffer),
    }
}

#[rustfmt::skip]
#[allow(clippy::cyclomatic_complexity)]
pub fn parse_request(data: &[u8], dialect: Dialect) -> IResult<&[u8], Request> {
    do_parse!(data,
        verify!(le_u16, |x| x == REQUEST_STRUCTURE_SIZE) >>
        padding: le_u8 >>
        flags: map_opt!(le_u8, Flags::from_bits) >>
        length: le_u32 >>
        offset: le_u64 >>
        file_id: map!(take!(16), FileId::from_slice) >>
        minimum_count: le_u32 >>
        channel_type: switch!(value!(dialect >= Dialect::Smb3_1_1),
            true => map_opt!(le_u32, ChannelType::from_u32) |
            false => map!(take!(4), |_| ChannelType::None)
        ) >>
        remaining_bytes: le_u32 >>
        channel_offset: le_u16 >>
        cond_with_error!(
            channel_type != ChannelType::None,
            verify!(value!(channel_offset), |offset| offset >= REQUEST_CONSTANT_SIZE)
        ) >>
        channel_length: le_u16 >>
        channel: cond_with_error!(
            channel_type != ChannelType::None,
            preceded!(
                take!(offset - u64::from(REQUEST_CONSTANT_SIZE)),
                map!(take!(channel_length), |buf| create_channel(buf, channel_type))
            )
        ) >>
        (Request {
            padding,
            read_unbuffered: flags.contains(Flags::READ_UNBUFFERED),
            length,
            offset,
            file_id,
            minimum_count,
            remaining_bytes,
            channel: channel.unwrap_or(Channel::None),
        })
    )
}

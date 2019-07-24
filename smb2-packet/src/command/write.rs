use super::{Channel, ChannelType};
use crate::{Dialect, FileId};
use bitflags::bitflags;
use num_traits::FromPrimitive;
use nom::{
    *, number::complete::{le_u8, le_u16, le_u32, le_u64},
};

const REQUEST_STRUCTURE_SIZE: u16 = 49;
const REQUEST_CONSTANT_SIZE: u16 = crate::header::STRUCTURE_SIZE + REQUEST_STRUCTURE_SIZE - 1;

#[cfg_attr(debug_assertions, derive(Debug))]
pub struct Request<'a> {
    pub file_id: FileId,
    pub offset: u64,
    pub remaining_bytes: u32,
    pub write_unbuffered: bool,
    pub write_through: bool,
    pub channel: Channel<'a>,
    pub data: &'a [u8],
}

#[cfg_attr(debug_assertions, derive(Debug))]
pub struct Response<'a> {
    pub data_remaining: u32,
    pub data: &'a [u8],
}

bitflags! {
    struct Flags: u8 {
        const WRITE_THROUGH = 0x01;
        const WRITE_UNBUFFERED = 0x02;
    }
}

struct Buffer {
    offset: u16,
    length: u32,
}

fn sort_buffers(
    channel_offset: u16,
    channel_length: u16,
    data_offset: u16,
    data_length: u32,
) -> (Buffer, Buffer) {
    if channel_offset > data_offset {
        (
            Buffer {
                offset: channel_offset,
                length: u32::from(channel_length),
            },
            Buffer {
                offset: data_offset,
                length: data_length,
            },
        )
    } else {
        (
            Buffer {
                offset: data_offset,
                length: data_length,
            },
            Buffer {
                offset: channel_offset,
                length: u32::from(channel_length),
            },
        )
    }
}

#[rustfmt::skip]
#[allow(clippy::cyclomatic_complexity)]
pub fn parse_request(data: &[u8], dialect: Dialect) -> IResult<&[u8], Request> {
    do_parse!(data,
        verify!(le_u16, |&x| x == REQUEST_STRUCTURE_SIZE) >>
        data_offset: le_u16 >>
        data_length: verify!(le_u32, |&l| l > 0) >>
        offset: le_u64 >>
        file_id: map!(take!(16), FileId::from_slice) >>
        channel_type: switch!(value!(dialect >= Dialect::Smb3_1_1),
            true => map_opt!(le_u32, ChannelType::from_u32) |
            false => map!(take!(4), |_| ChannelType::None)
        ) >>
        remaining_bytes: le_u32 >>
        channel_offset: map!(le_u16, |x| if channel_type == ChannelType::None { u16::max_value() } else { x }) >>
        channel_length: verify!(le_u16, |&x| channel_type == ChannelType::None || x > 0) >>
        flags: map_opt!(le_u8, Flags::from_bits) >>
        buffers: value!(sort_buffers(channel_offset, channel_length, data_offset, data_length)) >>
        verify!(value!(buffers.0.offset), |&offset| offset >= REQUEST_CONSTANT_SIZE) >>
        verify!(
            value!(buffers.1.offset),
            |&offset|
                channel_type == ChannelType::None ||
                u32::from(offset) > (u32::from(REQUEST_CONSTANT_SIZE) + buffers.0.length)
        ) >>
        first_buffer: preceded!(take!(REQUEST_CONSTANT_SIZE - buffers.0.offset), take!(buffers.0.length)) >>
        second_buffer: cond!(
            channel_type != ChannelType::None,
            preceded!(
                take!(u32::from(REQUEST_CONSTANT_SIZE - buffers.1.offset) - buffers.0.length),
                take!(buffers.1.length)
            )
        ) >>
        data: switch!(value!(second_buffer.is_some() && data_offset > channel_offset),
            true => value!(second_buffer.unwrap()) |
            false => value!(first_buffer)
        ) >>
        channel: switch!(value!(second_buffer.is_some() && channel_offset > data_offset),
            true => value!(super::create_channel(second_buffer.unwrap(), channel_type)) |
            false => value!(super::create_channel(first_buffer, channel_type))
        ) >>
        (Request {
            write_through: flags.contains(Flags::WRITE_THROUGH),
            write_unbuffered: flags.contains(Flags::WRITE_UNBUFFERED),
            remaining_bytes,
            offset,
            file_id,
            data,
            channel,
        })
    )
}

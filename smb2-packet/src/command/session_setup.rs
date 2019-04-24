use crate::{ Dialect, SecurityMode };
use num_traits::FromPrimitive;
use bitflags::bitflags;
use nom::*;

const REQUEST_STRUCTURE_SIZE: u16 = 25;
const _RESPONSE_STRUCTURE_SIZE: u16 = 9;

#[cfg_attr(debug_assertions, derive(Debug))]
pub struct Request<'a> {
    flags: Flags,
    security_mode: SecurityMode,
    capabilities: Capabilities,
    previous_session_id: u64,
    security_buffer: &'a [u8], 
}

#[cfg_attr(debug_assertions, derive(Debug))]
pub struct Response<'a>  {
    session_flags: SessionFlags,
    security_buffer: &'a [u8],
}

bitflags! {
    pub struct Flags: u8 {
        const BINDING = 0x01;
    }
}

bitflags! {
    pub struct Capabilities: u32 {
        const DFS = 0x01;
    }
}

bitflags! {
    pub struct SessionFlags: u16 {
        const IS_GUEST = 0x01;
        const IS_NULL = 0x02;
        const ENCRYPT_DATA = 0x03;
    }
}

#[rustfmt::skip]
#[allow(clippy::cyclomatic_complexity)]
impl<'a> Request<'a> {
    pub fn parse(data: &'a [u8], dialect: Dialect) -> nom::IResult<&'a [u8], Request> {
        let static_size = crate::header::HEADER_LEN + REQUEST_STRUCTURE_SIZE;
        println!("static_size={:x}", static_size);
        do_parse!(data,
            verify!(le_u16, |x| x == REQUEST_STRUCTURE_SIZE) >>
            flags: map_opt!(le_u8, Flags::from_bits) >>
            //cond!(dialect >= Dialect::Smb3_0_0, verify!(value!(flags.is_empty()), |x| x)) >>
            security_mode: map_opt!(le_u8, FromPrimitive::from_u8) >>
            capabilities: map!(le_u32, Capabilities::from_bits_truncate) >>
            take!(4) >> /* ignore Channel */
            security_buffer_offset: verify!(le_u16, |offset| offset >= static_size) >>
            security_buffer_length: le_u16 >>
            previous_session_id: le_u64 >>
            take!(security_buffer_offset - static_size) >> /* padding */
            security_buffer: take!(security_buffer_length) >>
            (Request {
                flags,
                security_mode,
                capabilities,
                previous_session_id,
                security_buffer,
            })
        )
    }
}


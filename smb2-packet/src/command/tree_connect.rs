use crate::utf16le_to_string;
use bitflags::bitflags;
use nom::*;
use num_derive::FromPrimitive;

const REQUEST_STRUCTURE_SIZE: u16 = 9;

#[cfg_attr(debug_assertions, derive(Debug))]
pub struct Request {
    pub flags: Flags,
    pub path: String,
}

#[cfg_attr(debug_assertions, derive(Debug))]
pub struct Response {
    pub share_type: ShareType,
    pub caching: Caching,
    pub share_flags: ShareFlags,
    pub maxmimal_access: u32, // TODO: replace by proper type
}

bitflags! {
    pub struct Flags: u8 {
        const CLUSTER_RECONNECT = 0x01;
        const REDIRECT_TO_OWNER = 0x02;
        const EXTENSION_RESENT = 0x04;
    }
}

#[repr(u8)]
#[cfg_attr(debug_assertions, derive(Debug))]
#[derive(FromPrimitive, PartialEq, Eq)]
pub enum Caching {
    Manual = 0x00,
    Auto = 0x01,
    Vdo = 0x02,
    No = 0x03,
}

bitflags! {
    pub struct ShareFlags: u32 {
        const DFS = 0x01;
        const DFS_ROOT = 0x02;
        const RESTRICT_EXCLUSIVE_OPENS = 0x0000_0100;
        const FORCE_SHARED_DELETE = 0x000_00200;
        const ACCESS_BASED_DIRECTORY_ENUM = 0x000_00800;
        const FORCE_LEVELII_OPLOCK = 0x000_01000;
        const ENABLE_HASH_V1 = 0x0000_2000;
        const ENABLE_HASH_V2 = 0x0000_4000;
        const SMB2_SHAREFLAG_ENCRYPT_DATA = 0x0000_8000;
        const IDENTITY_REMOTING = 0x0004_00000;
    }
}

bitflags! {
    pub struct Capabilites: u16 {
        const DFS = 0x08;
        const CONTINUOUS_AVAILABILITY = 0x10;
        const SCALEOUT = 0x20;
        const CLUSTER = 0x40;
        const ASYMMETRIC = 0x80;
        const REDIRECT_TO_OWNER = 0x100;
    }
}

#[repr(u8)]
#[cfg_attr(debug_assertions, derive(Debug))]
#[derive(FromPrimitive, PartialEq, Eq)]
pub enum ShareType {
    Disk = 0x01,
    Pipe = 0x02,
    Print = 0x03,
}

#[rustfmt::skip]
#[allow(clippy::cyclomatic_complexity)]
pub fn parse_request(data: &[u8]) -> IResult<&[u8], Request> {
    /* is off by one */
    let const_size = crate::header::STRUCTURE_SIZE + REQUEST_STRUCTURE_SIZE - 1;
    do_parse!(data,
        verify!(le_u16, |x| x == REQUEST_STRUCTURE_SIZE) >>
        flags: map_opt!(le_u16, |x| Flags::from_bits(x as u8)) >>
        path_offset: verify!(le_u16, |offset| offset >= const_size) >>
        path_length: le_u16 >>
        take!(path_offset - const_size) >> // padding
        path: map_res!(take!(path_length), utf16le_to_string) >>
        (Request {
            flags,
            path,
        })
    )
}

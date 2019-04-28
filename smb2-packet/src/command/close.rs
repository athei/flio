use crate::FileId;
use bitflags::bitflags;
use nom::*;
use std::time::SystemTime;

const REQUEST_STRUCTURE_SIZE: u16 = 24;

#[cfg_attr(debug_assertions, derive(Debug))]
pub struct Request {
    pub postquery_attrib: bool,
    pub file_id: FileId,
}

#[cfg_attr(debug_assertions, derive(Debug))]
pub struct Response {
    pub postquery_attrib: bool,
    pub creation_time: SystemTime,
    pub last_access_time: SystemTime,
    pub last_write_time: SystemTime,
    pub change_time: SystemTime,
    pub allocation_size: u64,
    pub end_of_file: u64,
    pub file_attributes: u32, // TODO: add type
}

bitflags! {
    struct Flags: u16 {
        const POSTQUERY_ATTRIB = 0x01;
    }
}

#[rustfmt::skip]
#[allow(clippy::cyclomatic_complexity)]
pub fn parse_request(data: &[u8]) -> IResult<&[u8], Request> {
    do_parse!(data,
        verify!(le_u16, |x| x == REQUEST_STRUCTURE_SIZE) >>
        flags: map_opt!(le_u16, Flags::from_bits) >>
        take!(4) >> /* reserved */
        file_id: map!(take!(16), FileId::from_slice) >>
        (Request {
            postquery_attrib: flags.contains(Flags::POSTQUERY_ATTRIB),
            file_id,
        })
    )
}

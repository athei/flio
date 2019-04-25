use nom::*;
use bitflags::bitflags;

const REQUEST_STRUCTURE_SIZE: u16 = 9;

#[cfg_attr(debug_assertions, derive(Debug))]
pub struct Request {
    pub flags: Flags,
    pub path: String,
}

bitflags! {
    pub struct Flags: u16 {
        const CLUSTER_RECONNECT = 0x01;
        const REDIRECT_TO_OWNER = 0x02;
        const EXTENSION_RESENT = 0x04;
    }
}

pub fn parse_request(data: &[u8]) -> IResult<&[u8], Request> {
    do_parse!(data,
        flags: map_opt!(le_u16, Flags::from_bits) >>
        (Request{
            flags,
            path: "LOL".into(),
        })
    )
}
use crate::FileId;
use nom::{
    *, number::complete::le_u16,
};

const REQUEST_STRUCTURE_SIZE: u16 = 24;

#[cfg_attr(debug_assertions, derive(Debug))]
pub struct Request {
    pub file_id: FileId,
}

#[rustfmt::skip]
#[allow(clippy::cognitive_complexity)]
pub fn parse_request(data: &[u8]) -> IResult<&[u8], Request> {
    do_parse!(data,
        verify!(le_u16, |&x| x == REQUEST_STRUCTURE_SIZE) >>
        take!(6) >> /* reserved */
        file_id: map!(take!(16), FileId::from_slice) >>
        (Request {
            file_id,
        })
    )
}

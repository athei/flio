use nom::{
    *, number::complete::le_u16,
};
use crate::IResult;

const REQUEST_STRUCTURE_SIZE: u16 = 4;

#[rustfmt::skip]
#[allow(clippy::cognitive_complexity)]
pub fn parse_request(data: &[u8]) -> IResult<&[u8], ()> {
    do_parse!(data,
        verify!(le_u16, |&x| x == REQUEST_STRUCTURE_SIZE) >>
        take!(2) >>
        (())
    )
}

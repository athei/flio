use nom::{
    bytes::streaming::tag,
    sequence::preceded,
    multi::length_data,
    number::streaming::be_u24,
};
use crate::IResult;

pub fn get_payload(data: &[u8]) -> IResult<&[u8], &[u8]> {
    preceded(tag(b"\x00"), length_data(be_u24))(data)
}

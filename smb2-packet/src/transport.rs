use nom::{
    IResult,
    bytes::streaming::tag,
    sequence::preceded,
    multi::length_data,
    number::streaming::be_u24,
};

pub fn get_payload(data: &[u8]) -> IResult<&[u8], &[u8]> {
    preceded(tag(b"\x00"), length_data(be_u24))(data)
}

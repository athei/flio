use nom::IResult;
use nom::bytes::streaming::{
    tag, take
};
use nom::sequence::preceded;

pub fn get_payload(&[u8]) -> IResult<&[u8], &[u8]> {
    preceded(tag(b"\x00"), length_)
}

//named!(pub get_payload, preceded!(tag(b"\x00"), length_bytes!(be_u24)));

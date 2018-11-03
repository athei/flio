use nom::*;

pub const HEADER_LEN: usize = 4;

named!(pub get_payload, preceded!(tag!("\0"), length_bytes!(be_u24)));

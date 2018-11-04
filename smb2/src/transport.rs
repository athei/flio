use nom::*;

named!(pub get_payload, preceded!(tag!("\0"), length_bytes!(be_u24)));

use nom::*;

named!(pub get_payload, preceded!(tag!(b"\x00"), length_bytes!(be_u24)));

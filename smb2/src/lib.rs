extern crate nom;
extern crate bitflags;
extern crate byteorder;

mod transport;
mod commands;
mod header;

use nom::*;

#[derive(Clone, Copy, PartialEq, PartialOrd)]
pub enum Dialect {
    Smb2_0_2 = 0x0202,
    Smb2_1_0 = 0x0210,
    Smb3_0_0 = 0x0300,
    Smb3_0_2 = 0x0302,
    Smb3_1_1 = 0x0311,
}

#[derive(Debug)]
pub struct Message<'a> {
    pub header: header::Header,
    pub body: &'a[u8]
}

pub fn parse_complete_payload(input: &[u8], dialect: Dialect) -> Result<Vec<Message>, nom::Err<&[u8]>> {
    let mut result = Vec::new();
    let mut cur = input;
    loop {
        match complete!(cur, apply!(header::parse, dialect)) {
            Ok((remainder, output)) => {
                result.push(Message { header: output.0, body: output.1 });
                if remainder.is_empty() {
                    break;
                }
               cur = remainder;
            }
            Err(x) => return Err(x),
        }
    }
    Ok(result)
}

pub fn parse(input: &[u8], dialect: Dialect) -> IResult<&[u8], Vec<Message>> {
    match transport::get_payload(input) {
        Ok((rest, out)) => parse_complete_payload(out, dialect).map(|i| (rest, i)),
        Err(x) => Err(x),
    }
}

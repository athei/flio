#![warn(clippy::all)]

pub mod command;
pub mod header;
pub mod smb1;
mod transport;

use nom::*;

use crate::command::error::ErrorResponse;
use crate::command::{Body, RequestBody};

#[derive(Clone, Copy, PartialEq, PartialOrd)]
pub enum Dialect {
    Smb2_0_2 = 0x0202,
    Smb2_1_0 = 0x0210,
    Smb3_0_0 = 0x0300,
    Smb3_0_2 = 0x0302,
    Smb3_1_1 = 0x0311,
}

#[derive(Debug)]
pub struct Request<'a> {
    pub header: header::RequestHeader,
    pub body: command::RequestBody<'a>,
}

#[derive(Debug)]
pub struct Response<'a> {
    pub header: header::ResponseHeader,
    pub body: Result<command::ReponseBody<'a>, (u32, ErrorResponse)>,
}

pub fn parse_request_complete(
    input: &[u8],
    dialect: Dialect,
) -> Result<Vec<Request>, nom::Err<&[u8]>> {
    let mut result: Vec<Request> = Vec::new();
    let mut cur = input;
    loop {
        match complete!(cur, apply!(header::parse, dialect)) {
            Ok((remainder, output)) => {
                result.push(Request {
                    header: output.header,
                    body: RequestBody::parse(output.command, output.body)?,
                });
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

pub fn parse_request(input: &[u8], dialect: Dialect) -> IResult<&[u8], Vec<Request>> {
    match transport::get_payload(input) {
        Ok((rem, out)) => parse_request_complete(out, dialect).map(|i| (rem, i)),
        Err(x) => Err(x),
    }
}

pub fn parse_smb1_nego_request_complete(input: &[u8]) -> Result<smb1::Request, nom::Err<&[u8]>> {
    match complete!(input, smb1::parse_negotiate) {
        Ok((rem, out)) => {
            assert!(
                rem.is_empty(),
                "Only pass complete segments into this function"
            );
            Ok(out)
        }
        Err(x) => Err(x),
    }
}

pub fn parse_smb1_nego_request(input: &[u8]) -> IResult<&[u8], smb1::Request> {
    match transport::get_payload(input) {
        Ok((rem, out)) => parse_smb1_nego_request_complete(out).map(|i| (rem, i)),
        Err(x) => Err(x),
    }
}

#![warn(clippy::all)]
#![warn(clippy::pedantic)]
#![deny(clippy::correctness)]
#![allow(clippy::useless_attribute)]

pub mod command;
pub mod header;
pub mod ntstatus;
pub mod smb1;
mod transport;

use crate::command::{Body, ReponseBody, RequestBody};
use crate::header::Header;
use crate::header::Request as RequestHeader;
use crate::header::Response as ResponseHeader;

#[repr(u16)]
#[derive(Clone, Copy, PartialEq, PartialOrd)]
#[allow(clippy::pub_enum_variant_names)]
pub enum Dialect {
    Smb2_0_2 = 0x0202,
    Smb2_1_0 = 0x0210,
    Smb3_0_0 = 0x0300,
    Smb3_0_2 = 0x0302,
    Smb3_1_1 = 0x0311,
}

#[cfg_attr(debug_assertions, derive(Debug))]
pub struct Request<'a> {
    pub header: RequestHeader,
    pub body: RequestBody<'a>,
}

#[cfg_attr(debug_assertions, derive(Debug))]
pub struct Response<'a> {
    pub header: ResponseHeader,
    pub body: ReponseBody<'a>,
}

pub fn parse<'a, T>(input: &'a [u8], dialect: Dialect) -> nom::IResult<&'a [u8], Vec<T>>
    where T: Packet<'a>
{
    match transport::get_payload(input) {
        Ok((rem, out)) => T::parse(out, dialect).map(|i| (rem, i)),
        Err(x) => Err(x),
    }
}

pub fn parse_smb1_nego_request(input: &[u8]) -> nom::IResult<&[u8], smb1::Request> {
    match transport::get_payload(input) {
        Ok((rem, out)) => parse_smb1_nego_request_complete(out).map(|i| (rem, i)),
        Err(x) => Err(x),
    }
}

fn parse_smb1_nego_request_complete(input: &[u8]) -> Result<smb1::Request, nom::Err<&[u8]>> {
    use nom::complete;
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

pub trait Packet<'a>
where
    Self: Sized,
{
    type Header: Header;
    type Body: Body<'a>;

    fn new(header: Self::Header, body: Self::Body) -> Self;

    fn parse(input: &'a [u8], dialect: Dialect) -> Result<Vec<Self>, nom::Err<&[u8]>> {
        use nom::{apply, complete};
        let mut result = Vec::new();
        let mut cur = input;
        loop {
            match complete!(cur, apply!(Self::Header::parse, dialect)) {
                Ok((remainder, output)) => {
                    let status = output.header.get_status();
                    result.push(Self::new(
                        output.header,
                        Self::Body::parse(output.command, output.body, status)?,
                    ));
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
}

impl<'a> Packet<'a> for Request<'a> {
    type Header = RequestHeader;
    type Body = RequestBody<'a>;

    fn new(header: Self::Header, body: Self::Body) -> Self {
        Request { header, body }
    }
}

impl<'a> Packet<'a> for Response<'a> {
    type Header = ResponseHeader;
    type Body = ReponseBody<'a>;

    fn new(header: Self::Header, body: Self::Body) -> Self {
        Response { header, body }
    }
}

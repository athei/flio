#![warn(clippy::all)]
#![warn(clippy::pedantic)]
#![deny(clippy::correctness)]

pub mod command;
pub mod header;
pub mod ntstatus;
pub mod smb1;
mod transport;

use crate::command::{Body, RequestBody, ResponseBody};
use crate::header::Header;
use crate::header::Request as RequestHeader;
use crate::header::Response as ResponseHeader;
use num_derive::FromPrimitive;
use std::convert::TryInto;
use std::ops::Deref;

//pub type IResult<I, O, E = nom::error::VerboseError<I>> = Result<(I, O), nom::Err<E>>;
pub type IResult<I, O> = nom::IResult<I, O>;

#[repr(u16)]
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, FromPrimitive)]
#[cfg_attr(debug_assertions, derive(Debug))]
#[allow(clippy::pub_enum_variant_names)]
pub enum Dialect {
    Smb2_0_2 = 0x0202,
    Smb2_1_0 = 0x0210,
    Smb3_0_0 = 0x0300,
    Smb3_0_2 = 0x0302,
    Smb3_1_1 = 0x0311,
}

#[cfg_attr(debug_assertions, derive(Debug))]
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct FileId {
    data: [u8; 16],
}

impl FileId {
    fn from_slice(id: &[u8]) -> Self {
        let data: [u8; 16] = id.try_into().unwrap();
        Self { data }
    }
}

#[cfg_attr(debug_assertions, derive(Debug))]
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct ClientGuid {
    data: [u8; 16],
}

impl ClientGuid {
    fn from_slice(id: &[u8]) -> Self {
        let data: [u8; 16] = id.try_into().unwrap();
        Self { data }
    }
}

impl Deref for ClientGuid {
    type Target = [u8; 16];

    fn deref(&self) -> &Self::Target {
        &self.data
    }
}

#[cfg_attr(debug_assertions, derive(Debug))]
pub struct Request<'a> {
    pub header: RequestHeader,
    pub body: RequestBody<'a>,
}

#[cfg_attr(debug_assertions, derive(Debug))]
pub struct Response<'a> {
    pub header: ResponseHeader,
    pub body: ResponseBody<'a>,
}

pub fn parse<'a, T>(input: &'a [u8], dialect: Dialect) -> IResult<&'a [u8], Vec<T>>
where
    T: Packet<'a>,
{
    match transport::get_payload(input) {
        Ok((rem, out)) => Ok((rem, T::parse(out, dialect)?.1)),
        Err(x) => Err(x),
    }
}

pub fn parse_smb1_nego_request(input: &[u8]) -> IResult<&[u8], smb1::NegotiateRequest> {
    match transport::get_payload(input) {
        Ok((rem, out)) => Ok((rem, parse_smb1_nego_request_complete(out)?.1)),
        Err(x) => Err(x),
    }
}

fn parse_smb1_nego_request_complete(
    input: &[u8],
) -> IResult<&[u8], smb1::NegotiateRequest> {
    match smb1::parse_negotiate(input) {
        Ok((rem, out)) => {
            assert!(
                rem.is_empty(),
                "Only pass complete segments into this function"
            );
            Ok((rem, out))
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

    fn parse(input: &'a [u8], dialect: Dialect) -> IResult<&'a [u8], Vec<Self>> {
        let mut result = Vec::new();
        let mut cur = input;
        loop {
            match Self::Header::parse(cur, dialect) {
                Ok((remainder, output)) => {
                    let status = output.header.get_status();
                    result.push(Self::new(
                        output.header,
                        Self::Body::parse(output.body, dialect, output.command, status)?.1,
                    ));
                    if remainder.is_empty() {
                        break;
                    }
                    cur = remainder;
                }
                Err(x) => return Err(x),
            }
        }
        Ok((cur, result))
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
    type Body = ResponseBody<'a>;

    fn new(header: Self::Header, body: Self::Body) -> Self {
        Response { header, body }
    }
}

#[allow(clippy::cast_ptr_alignment)]
fn utf16le_to_string(data: &[u8]) -> Result<String, String> {
    if data.len() % 2 != 0 {
        return Err("UTF-16 string length must be even".to_string());
    }

    // We cannot cast u8 -> u16 because of alignment requirements
    // Also this allows us to twist the endianess when needed
    let mut buffer = Vec::with_capacity(data.len() / 2);
    for (i, val) in data.iter().enumerate().skip(1).step_by(2) {
        buffer.push((u16::from(*val) << 8) | u16::from(data[i - 1]));
    }

    String::from_utf16(&buffer).map_err(|err| err.to_string())
}

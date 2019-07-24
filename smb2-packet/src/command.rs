pub mod close;
pub mod create;
pub mod error;
pub mod flush;
pub mod logoff;
pub mod negotiate;
pub mod read;
pub mod session_setup;
pub mod tree_connect;
pub mod tree_disconnect;
pub mod write;

use crate::header::Command;
use crate::ntstatus::NTStatus;
use crate::Dialect;
use num_derive::FromPrimitive;
use nom::IResult;

#[cfg_attr(debug_assertions, derive(Debug))]
pub enum RequestBody<'a> {
    Negotiate(negotiate::Request<'a>),
    SessionSetup(session_setup::Request<'a>),
    Logoff,
    TreeConnect(tree_connect::Request),
    TreeDisconnect,
    Create(create::Request),
    Close(close::Request),
    Flush(flush::Request),
    Read(read::Request<'a>),
    NotImplemented { command: Command, body: &'a [u8] },
}

#[cfg_attr(debug_assertions, derive(Debug))]
pub enum ResponseBody<'a> {
    Negotiate(negotiate::Response<'a>),
    SessionSetup(session_setup::Response<'a>),
    Logoff,
    TreeConnect(tree_connect::Response),
    TreeDisconnect,
    Create(create::Response),
    Close(close::Response),
    Flush,
    Error(error::Response),
    Read(read::Response<'a>),
    NotImplemented { command: Command, body: &'a [u8] },
}

#[repr(u8)]
#[cfg_attr(debug_assertions, derive(Debug))]
#[derive(FromPrimitive, PartialEq, Eq, Clone, Copy)]
enum ChannelType {
    None = 0x00,
    RdmaV1 = 0x01,
    RdmaV1Invalidate = 0x02,
}

#[cfg_attr(debug_assertions, derive(Debug))]
pub enum Channel<'a> {
    None,
    RdmaV1(&'a [u8]),
    RdmaV1Invalidate(&'a [u8]),
}

pub trait Body<'a>
where
    Self: Sized,
{
    fn parse(
        body: &'a [u8],
        dialect: Dialect,
        command: Command,
        status: Option<NTStatus>,
    ) -> IResult<&'a [u8], Self>;
}

impl<'a> Body<'a> for RequestBody<'a> {
    fn parse(
        body: &'a [u8],
        dialect: Dialect,
        command: Command,
        _status: Option<NTStatus>,
    ) -> IResult<&'a [u8], Self> {
        let cmd = match command {
            Command::Negotiate => {
                let res = negotiate::parse(body)?;
                (res.0, RequestBody::Negotiate(res.1))
            },
            Command::SessionSetup => {
                let res = session_setup::parse_request(body, dialect)?;
                (res.0, RequestBody::SessionSetup(res.1))
            },
            Command::Logoff => {
                let res = logoff::parse_request(body)?;
                (res.0, RequestBody::Logoff)
            },
            Command::TreeConnect => {
                let res = tree_connect::parse_request(body)?;
                (res.0, RequestBody::TreeConnect(res.1))
            },
            Command::TreeDisconnect => {
                let res = tree_disconnect::parse_request(body)?;
                (res.0, RequestBody::TreeDisconnect)
            },
            Command::Create => {
                let res = create::parse_request(body, dialect)?;
                (res.0, RequestBody::Create(res.1))
            },
            Command::Close => {
                let res = close::parse_request(body)?;
                (res.0, RequestBody::Close(res.1))
            },
            Command::Flush => {
                let res = flush::parse_request(body)?;
                (res.0, RequestBody::Flush(res.1))
            },
            Command::Read => {
                let res = read::parse_request(body, dialect)?;
                (res.0, RequestBody::Read(res.1))
            },
            _ => (body, RequestBody::NotImplemented { command, body }),
        };
        Ok(cmd)
    }
}

impl<'a> Body<'a> for ResponseBody<'a> {
    fn parse(
        body: &'a [u8],
        _dialect: Dialect,
        command: Command,
        status: Option<NTStatus>,
    ) -> IResult<&'a [u8], Self> {
        let status = status.unwrap();
        if !status.is_success() {
            return Ok((body, ResponseBody::NotImplemented { command, body }));
        }
        Ok((body, ResponseBody::Error(error::Response { status, command })))
    }
}

fn create_channel(buffer: &[u8], channel_type: ChannelType) -> Channel<'_> {
    match channel_type {
        ChannelType::None => Channel::None,
        ChannelType::RdmaV1 => Channel::RdmaV1(buffer),
        ChannelType::RdmaV1Invalidate => Channel::RdmaV1Invalidate(buffer),
    }
}

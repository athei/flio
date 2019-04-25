pub mod error;
pub mod negotiate;
pub mod session_setup;

use crate::ntstatus::NTStatus;
use crate::Dialect;
use num_derive::FromPrimitive;

#[repr(u16)]
#[derive(FromPrimitive, PartialEq, Eq)]
#[cfg_attr(debug_assertions, derive(Debug))]
pub enum Command {
    Negotiate = 0x00,
    SessionSetup = 0x01,
    Logoff = 0x02,
    TreeConnect = 0x03,
    TreeDisconnect = 0x04,
    Create = 0x05,
    Close = 0x06,
    Flush = 0x07,
    Read = 0x08,
    Write = 0x09,
    Lock = 0x0A,
    Ioctl = 0x0B,
    Cancel = 0x0C,
    Echo = 0x0D,
    QueryDirectory = 0x0E,
    ChangeNotify = 0x0F,
    QueryInfo = 0x10,
    SetInfo = 0x11,
    OplockBreak = 0x12,
}

#[cfg_attr(debug_assertions, derive(Debug))]
pub enum RequestBody<'a> {
    Negotiate(negotiate::Request<'a>),
    SessionSetup(session_setup::Request<'a>),
    NotImplemented { command: Command, body: &'a [u8] },
}

#[cfg_attr(debug_assertions, derive(Debug))]
pub enum ResponseBody<'a> {
    Negotiate(negotiate::Response<'a>),
    SessionSetup(session_setup::Response<'a>),
    Error(error::Response),
    NotImplemented { command: Command, body: &'a [u8] },
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
    ) -> Result<Self, nom::Err<&'a [u8]>>;
}

impl<'a> Body<'a> for RequestBody<'a> {
    fn parse(
        body: &'a [u8],
        dialect: Dialect,
        command: Command,
        _status: Option<NTStatus>,
    ) -> Result<Self, nom::Err<&'a [u8]>> {
        let cmd = match command {
            Command::Negotiate => RequestBody::Negotiate(negotiate::parse(body)?.1),
            Command::SessionSetup => {
                RequestBody::SessionSetup(session_setup::Request::parse(body, dialect)?.1)
            }
            _ => RequestBody::NotImplemented { command, body },
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
    ) -> Result<Self, nom::Err<&'a [u8]>> {
        let status = status.unwrap();
        if !status.is_success() {
            return Ok(ResponseBody::NotImplemented { command, body });
        }
        Ok(ResponseBody::Error(error::Response { status, command }))
    }
}

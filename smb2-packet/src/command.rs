pub mod error;
pub mod negotiate;

use num_derive::FromPrimitive;

use crate::ntstatus::NTStatus;

#[derive(FromPrimitive, PartialEq)]
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
    Negotiate(negotiate::Request),
    NotImplemented { command: Command, body: &'a [u8] },
}

#[cfg_attr(debug_assertions, derive(Debug))]
pub enum ReponseBody<'a> {
    Negotiate(negotiate::Response),
    Error(error::Response),
    NotImplemented { command: Command, body: &'a [u8] },
}

pub trait Body<'a>
where
    Self: Sized,
{
    fn parse(
        command: Command,
        body: &'a [u8],
        status: Option<NTStatus>,
    ) -> Result<Self, nom::Err<&'a [u8]>>;
}

impl<'a> Body<'a> for RequestBody<'a> {
    fn parse(
        command: Command,
        body: &'a [u8],
        _status: Option<NTStatus>,
    ) -> Result<Self, nom::Err<&'a [u8]>> {
        Ok(RequestBody::NotImplemented { command, body })
    }
}

impl<'a> Body<'a> for ReponseBody<'a> {
    fn parse(
        command: Command,
        body: &'a [u8],
        status: Option<NTStatus>,
    ) -> Result<Self, nom::Err<&'a [u8]>> {
        let status = status.unwrap();
        if !status.is_success() {
            return Ok(ReponseBody::NotImplemented { command, body });
        }
        Ok(ReponseBody::Error(error::Response { status, command }))
    }
}
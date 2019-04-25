pub mod error;
pub mod negotiate;
pub mod session_setup;
pub mod logoff;

use crate::ntstatus::NTStatus;
use crate::header::Command;
use crate::Dialect;

#[cfg_attr(debug_assertions, derive(Debug))]
pub enum RequestBody<'a> {
    Negotiate(negotiate::Request<'a>),
    SessionSetup(session_setup::Request<'a>),
    Logoff,
    NotImplemented { command: Command, body: &'a [u8] },
}

#[cfg_attr(debug_assertions, derive(Debug))]
pub enum ResponseBody<'a> {
    Negotiate(negotiate::Response<'a>),
    SessionSetup(session_setup::Response<'a>),
    Logoff,
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
                RequestBody::SessionSetup(session_setup::parse_request(body, dialect)?.1)
            },
            Command::Logoff => {
                println!("LOL");
                logoff::parse_request(body)?;
                RequestBody::Logoff
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

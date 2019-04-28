pub mod close;
pub mod create;
pub mod error;
pub mod flush;
pub mod logoff;
pub mod negotiate;
pub mod session_setup;
pub mod tree_connect;
pub mod tree_disconnect;

use crate::header::Command;
use crate::ntstatus::NTStatus;
use crate::Dialect;

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
            }
            Command::Logoff => {
                logoff::parse_request(body)?;
                RequestBody::Logoff
            }
            Command::TreeConnect => RequestBody::TreeConnect(tree_connect::parse_request(body)?.1),
            Command::TreeDisconnect => {
                tree_disconnect::parse_request(body)?;
                RequestBody::TreeDisconnect
            }
            Command::Create => RequestBody::Create(create::parse_request(body, dialect)?.1),
            Command::Close => RequestBody::Close(close::parse_request(body)?.1),
            Command::Flush => RequestBody::Flush(flush::parse_request(body)?.1),
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

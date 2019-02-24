pub mod error;
pub mod negotiate;

use num_derive::FromPrimitive;

#[derive(Debug, FromPrimitive, PartialEq)]
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

pub enum RequestBody {
    Negotiate(negotiate::NegotiateRequest),
}

pub enum ReponseBody {
    Negotiate(negotiate::NegotiateResponse)
}

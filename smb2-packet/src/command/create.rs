use crate::utf16le_to_string;
use crate::Dialect;
use crate::FileId;
use bitflags::bitflags;
use nom::*;
use num_derive::FromPrimitive;
use num_traits::FromPrimitive;
use std::time::SystemTime;

const REQUEST_STRUCTURE_SIZE: u16 = 57;
const REQUEST_CONSTANT_SIZE: u16 = crate::header::STRUCTURE_SIZE + REQUEST_STRUCTURE_SIZE - 1;

#[cfg_attr(debug_assertions, derive(Debug))]
pub struct Request {
    pub requested_oplock_level: OplockLevel,
    pub impersonation_level: ImpersonationLevel,
    pub desired_access: u32,  // TODO: add proper type
    pub file_attributes: u32, // TODO: add type
    pub share_access: ShareAccess,
    pub create_disposition: CreateDisposition,
    pub create_options: u32, // TODO: add type
    pub name: String,
    // TODO: add contexts
}

#[cfg_attr(debug_assertions, derive(Debug))]
pub struct Response {
    pub oplock_level: OplockLevel,
    pub flags: Flags,
    pub create_action: CreateAction,
    pub creation_time: SystemTime,
    pub last_access_time: SystemTime,
    pub change_time: SystemTime,
    pub allocation_size: u64,
    pub end_of_file: u64,
    pub file_attributes: u32, // TODO: add type
    pub file_id: FileId,
    // TODO: add create contexts
}

#[repr(u8)]
#[cfg_attr(debug_assertions, derive(Debug))]
#[derive(FromPrimitive, PartialEq, Eq)]
pub enum OplockLevel {
    No = 0x00,
    II = 0x01,
    Exclusive = 0x08,
    Batch = 0x09,
    Lease = 0xFF,
}

#[repr(u8)]
#[cfg_attr(debug_assertions, derive(Debug))]
#[derive(FromPrimitive, PartialEq, Eq)]
pub enum ImpersonationLevel {
    Anonymous = 0x00,
    Identification = 0x01,
    Impersonation = 0x02,
    Delegate = 0x03,
}

bitflags! {
    pub struct ShareAccess: u8 {
        const READ = 0x01;
        const WRITE = 0x02;
        const DELETE = 0x04;
    }
}

#[repr(u8)]
#[cfg_attr(debug_assertions, derive(Debug))]
#[derive(FromPrimitive, PartialEq, Eq)]
pub enum CreateDisposition {
    Supersede = 0x00,
    Open = 0x01,
    Create = 0x02,
    OpenIf = 0x03,
    Overwrite = 0x04,
    OverwriteIf = 0x05,
}

bitflags! {
    pub struct Flags: u8 {
        const REPARSEPOINT = 0x01;
    }
}

#[repr(u8)]
#[cfg_attr(debug_assertions, derive(Debug))]
#[derive(FromPrimitive, PartialEq, Eq)]
pub enum CreateAction {
    Superseded = 0x00,
    Opened = 0x01,
    Created = 0x02,
    Overwritten = 0x03,
}

#[rustfmt::skip]
#[allow(clippy::cyclomatic_complexity)]
pub fn parse_request(data: &[u8], _dialect: Dialect) -> IResult<&[u8], Request> {
    do_parse!(data,
        verify!(le_u16, |x| x == REQUEST_STRUCTURE_SIZE) >>
        take!(1) >> /* ignore security flags */
        requested_oplock_level: map_opt!(le_u8, FromPrimitive::from_u8) >>
        impersonation_level: map_opt!(le_u32, FromPrimitive::from_u32) >>
        take!(16) >> // SmbCreateFlags ignore + reserved
        desired_access: le_u32 >>
        file_attributes: le_u32 >>
        share_access: map_opt!(le_u32, |x| ShareAccess::from_bits(x as u8)) >>
        create_disposition: map_opt!(le_u32, FromPrimitive::from_u32) >>
        create_options: le_u32 >>
        name_offset: verify!(le_u16, |offset| offset >= REQUEST_CONSTANT_SIZE) >>
        name_length: le_u16 >>
        _create_context_offset: le_u32 >>
        _create_context_length: le_u32 >>
        take!(name_offset - REQUEST_CONSTANT_SIZE) >>
        name: map_res!(take!(name_length), utf16le_to_string) >>
        (Request {
           requested_oplock_level,
           impersonation_level,
           desired_access,
           file_attributes,
           share_access,
           create_disposition,
           create_options,
           name,
        })
    )
}

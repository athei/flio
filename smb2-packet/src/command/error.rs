use super::Command;

use crate::ntstatus::NTStatus;

#[cfg_attr(debug_assertions, derive(Debug))]
pub struct Response {
    // This is the status from the header
    pub status: NTStatus,
    // This is the failed command
    pub command: Command,
    // TODO: add remaining fields
}

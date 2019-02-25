use super::Command;

use crate::ntstatus::NTStatus;

#[derive(Debug)]
pub struct ErrorResponse {
    // This is the status from the header
    pub status: NTStatus,
    // This is the failed command
    pub command: Command,
    // TODO: add remaining fields
}

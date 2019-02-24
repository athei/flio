use super::Command;

#[derive(Debug)]
pub struct ErrorResponse {
    // This is the status from the header
    pub status: u32,
    // This is the failed command
    pub command: Command,
    // TODO: add remaining fields
}

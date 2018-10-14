use nom::be_u24;

pub const TRANSPORT_SIZE: usize = 4;

struct Header {
    credit_charge: u16,
    channel_sequence: Option<u16>,
    status: Option<u32>,
    command: u16,
    credit_request: u16,
    flags: u32,
    message_id: u64,
    async_id: Option<u64>,
    tree_id: Option<u32>,
    session_id: u64,
    signature: [u8; 16]
}

named!(tcp_transport<&[u8], u32>, preceded!(tag!("\0"), be_u24));

pub fn extract_message_length(head: &[u8]) -> Option<u32> {
    return match tcp_transport(head) {
        Ok((_, o)) => Some(o),
        _ => None
    }
}

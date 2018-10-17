use nom::{be_u16, be_u24, be_u32, be_u64, be_u8, IResult};

pub const TRANSPORT_SIZE: usize = 4;
pub const HEADER_SIZE: usize = 64;
pub const SIG_SIZE: usize = 16;

enum Dialect {
    SMB_2_0_2 = 0x0202,
    SMB_2_1_0 = 0x0210,
    SMB_3_0_0 = 0x0300,
    SMB_3_0_2 = 0x0302,
    SMB_3_1_1 = 0x0311,
    SMB_Wildcard = 0x02FF,
}

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
    signature: [u8; SIG_SIZE]
}

struct Message {
    header: Header,
    body: Vec<u8>,
}

fn copy_sig(input: &[u8]) -> [u8; SIG_SIZE] {
    let mut ret = [0; SIG_SIZE];
    ret.copy_from_slice(input);
    ret
}

named!(tcp_transport<u32>, preceded!(tag!("\0"), be_u24));

// TODO: bitflags und byteorder crates nutzen

fn smb_header(input: &[u8], dialect: Dialect) -> IResult<&[u8], Message> {
    do_parse!(input,
        verify!(be_u8, |v| v == 0xFE) >>
        tag!("SMB") >>
        verify!(be_u16, |v| v == HEADER_SIZE as u16) >>
        credit_charge: be_u16 >>
        status: take!(4) >>
        command: be_u16 >>
        credit_request: be_u16 >>
        flags: be_u32 >>
        next_command: be_u32 >>
        message_id: be_u64 >>
        cond!(flags != 0x01, take!(4)) >>
        tree_id: cond!(flags != 0x01, be_u32) >>
        async_id: cond!(flags == 0x01, be_u64) >>
        session_id: be_u64 >>
        signature: map!(take!(16), copy_sig) >>
        body: switch!(value!(next_command > HEADER_SIZE as u32),
            true => take!(next_command - HEADER_SIZE as u32) |
            false => take_while!(|_| true)
        ) >>
        (Message {
            header: Header {
                credit_charge: credit_charge,
                channel_sequence: None,
                status: None,
                command: command,
                credit_request: credit_request,
                flags: flags,
                message_id: message_id,
                async_id: async_id,
                tree_id: tree_id,
                session_id: session_id,
                signature: signature,
            },
            body: body.to_vec(),
        })
    )
}

pub fn extract_message_length(head: &[u8]) -> Option<u32> {
    return match tcp_transport(head) {
        Ok((_, o)) => Some(o),
        _ => None,
    };
}

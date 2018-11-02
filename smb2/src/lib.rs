extern crate nom;
extern crate bitflags;
extern crate byteorder;

mod transport;
mod commands;
mod header;

#[derive(Clone, Copy, PartialEq, PartialOrd)]
pub enum Dialect {
    Smb2_0_2 = 0x0202,
    Smb2_1_0 = 0x0210,
    Smb3_0_0 = 0x0300,
    Smb3_0_2 = 0x0302,
    Smb3_1_1 = 0x0311,
}

#[derive(Debug)]
pub struct Message {
    pub header: header::Header,
}

pub use transport::get_payload as remove_transport_header;

pub fn parse_messages(input: &[u8], dialect: Dialect) -> Result<Vec<Message>, ()> {
    let mut result = Vec::new();
    let mut cur = input;
    loop {
        if let Ok((remainder, output)) = header::parse(cur, dialect) {
            result.push(Message { header: output.0 });
            if remainder.is_empty() {
                break;
            }
            cur = remainder;
        } else {
            return Err(());
        }
    }
    Ok(result)
}

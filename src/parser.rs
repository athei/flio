use nom::be_u24;
use nom::Err::Incomplete;
use nom::Needed::Size;

pub struct Parser {
    buffer: Vec<u8>,
    needed: usize,
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
    signature: [u8; 16]
}

named!(tcp_transport, preceded!(tag!("\0"), length_data!(be_u24)));

impl Parser {
    pub fn new() -> Parser {
        Parser {
            buffer: Vec::new(),
            needed: 0,
        }
    }

    fn parse(&mut self, data: Option<&[u8]>) -> bool {
        let mut stopped_at: usize = 0;

        {
            let work = data.unwrap_or(&self.buffer);

            loop {
                match tcp_transport(work) {
                    Ok((i , o)) => {
                        println!("Found SMB(2) packet of size {}", o.len());
                        stopped_at = i.as_ptr() as usize - work.as_ptr() as usize;
                        if i.is_empty() {
                            self.needed = 0;
                            return true;
                        }
                    },
                    Err(Incomplete(x)) => {
                        if let Size(needed) = x {
                            self.needed = needed;
                        } else {
                            self.needed = 0;
                        }
                        break;
                    },
                    Err(_) => { return false; }
                }
            }
        }

        if stopped_at == 0 {
            return true;
        }

        if data.is_some() {
            self.buffer.extend_from_slice(&data.unwrap()[stopped_at..]);
        } else {
            self.buffer.drain(..stopped_at);
        }

        return true;
    }

    pub fn add_data(&mut self, data: &[u8]) -> bool {
        if self.buffer.is_empty() {
            return self.parse(Some(data));
        }

        self.buffer.extend_from_slice(data);

        if data.len() < self.needed {
            self.needed -= data.len();
            return true;
        }

        return self.parse(None);
    }
}


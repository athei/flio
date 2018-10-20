use nom::{be_u24};

pub const HEADER_LEN: usize = 4;

named!(tcp_transport<u32>, preceded!(tag!("\0"), be_u24));

pub fn get_payload(head: &[u8]) -> Option<&[u8]> {
    return match tcp_transport(head) {
        Ok((_, len)) => {
            let start = HEADER_LEN;
            let end = start + len as usize;
            if end - start > head.len() {
                None
            }
            else {
                Some(&head[start..end])
            }
        }
        _ => None,
    };
}

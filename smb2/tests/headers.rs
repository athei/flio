#![warn(clippy::all)]

mod common;

use crate::common::parse_pcap;

#[test]
fn request_headers() -> std::io::Result<()> {
    let mut buffer = Vec::new();
    let requests = parse_pcap("all_Requests", &mut buffer);
    assert!(requests.is_ok());
    let requests = requests.unwrap();
    let len = requests.requests.len(); 
    let len_should = 791;
    assert!(len == len_should, "Length should be {} but is {}", len_should, len);
    Ok(())
}

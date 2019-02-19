#![warn(clippy::all)]

mod common;

use std::path::PathBuf;
use crate::common::parse_pcap;

#[test]
fn request_headers() -> std::io::Result<()> {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("tests/data/all_requests.pcapng");
    let mut buffer = Vec::new();

    let requests = parse_pcap(&path, &mut buffer);
    assert!(requests.is_ok());
    let requests = requests.unwrap();
    let len = requests.requests.len(); 
    let len_should = 791;
    assert!(len == len_should, "Length should be {} but is {}", len_should, len);
    Ok(())
}

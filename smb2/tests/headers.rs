#![warn(clippy::all)]

mod common;

use std::path::PathBuf;
use std::fs::read_dir;
use crate::common::parse_pcap;

#[test]
fn headers() -> std::io::Result<()> {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("tests/data");
    let mut buffer = Vec::new();

    for entry in read_dir(path)? {
        let entry = entry?;
        println!("Reading {:?}", entry.file_name());
        let requests = parse_pcap(&entry.path(), &mut buffer);
        assert!(requests.is_ok());
        let requests = requests.unwrap();
        assert!(!requests.requests.is_empty());
    }

    Ok(())
}

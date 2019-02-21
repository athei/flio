#![warn(clippy::all)]

mod common;

use crate::common::parse_pcap;

#[test]
fn all_requests_just_parse() {
    let mut buffer = Vec::new();
    let requests = parse_pcap("all_Requests", &mut buffer).unwrap();
    let len = requests.len(); 
    let len_should = 791;
    assert!(len == len_should, "Length should be {} but is {}", len_should, len);
}

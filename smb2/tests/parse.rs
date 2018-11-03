extern crate ether;
extern crate slice_deque;
extern crate smb2;
extern crate nom;

use ether::packet::datalink::ethernet;
use ether::packet::datalink::ethernet::EtherType::IPv4;
use ether::packet::network::ipv4;
use ether::packet::network::ipv4::Protocol::TCP;
use ether::packet::transport::tcp;
use ether::pcap;
use std::path::PathBuf;
use slice_deque::SliceDeque;
use nom::Err;

#[test]
fn parse_navigation() {
    use std::fs::File;

    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("tests/data/navigation.pcap");
    let file = File::open(path).unwrap();
    let pcap = pcap::PacketCapture::new(file);
    let (_, records) = pcap.parse().unwrap();
    let mut buffer = SliceDeque::<u8>::new();

    for record in records {
        let frame = ethernet::Frame::new(&record.payload);
        if frame.ethertype() != IPv4 {
            continue;
        }
        let packet = ipv4::Packet::new(frame.payload());
        if packet.protocol() != TCP {
            continue;
        }
        let segment = tcp::Packet::new(packet.payload());
        if segment.source() != 445 && segment.destination() != 445 {
            continue;
        }
        if segment.payload().len() == 0 {
            continue;
        }

        buffer.extend_from_slice(segment.payload());

        let mut after_remove;

        match smb2::parse(&buffer, smb2::Dialect::Smb3_0_2) {
            Ok((remaining, messages)) => {
                println!("{:?}", messages);
                after_remove = remaining.len();
            },
            Err(Err::Incomplete(_)) => continue,
            _ => {
                assert!(false);
                return;
            }
        };

        buffer.truncate_front(after_remove);
    }
}

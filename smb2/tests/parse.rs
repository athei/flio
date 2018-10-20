extern crate ether;
extern crate slice_deque;
extern crate smb2;

use ether::packet::datalink::ethernet;
use ether::packet::datalink::ethernet::EtherType::IPv4;
use ether::packet::network::ipv4;
use ether::packet::network::ipv4::Protocol::TCP;
use ether::packet::transport::tcp;
use ether::pcap;
use std::path::PathBuf;
use slice_deque::SliceDeque;

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
        if buffer.len() < smb2::transport::HEADER_LEN {
            continue;
        }

        let mut after_remove;

        {
            let body = smb2::transport::get_payload(&buffer);

            if body.is_none() {
                println!("Error decoding netbios header.");
                return;
            }

            let body = body.unwrap();
            after_remove = buffer.len() - (body.len() + smb2::transport::HEADER_LEN);
            println!("SMB(2) message of len {} found", body.len());
            let msg = smb2::parse_messages(body, smb2::Dialect::Smb3_0_2);
            assert!(msg.is_ok());
        }

        if after_remove > 0 {
            buffer.truncate_front(after_remove);
        }
    }
}

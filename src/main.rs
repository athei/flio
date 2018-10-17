#[macro_use]
extern crate nom;
extern crate ether;
extern crate slice_deque;

mod parser;

use ether::packet::datalink::ethernet;
use ether::packet::datalink::ethernet::EtherType::IPv4;
use ether::packet::network::ipv4;
use ether::packet::network::ipv4::Protocol::TCP;
use ether::packet::transport::tcp;
use ether::pcap;
use slice_deque::SliceDeque;

fn run() {
    use std::fs::File;

    let file = File::open("navigation.pcap").unwrap();
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
        if buffer.len() < parser::TRANSPORT_SIZE {
            continue;
        }
        let len = parser::extract_message_length(&buffer);
        if let Some(len) = len {
            let to_remove = len as usize + parser::TRANSPORT_SIZE;
            if to_remove > buffer.len() {
                continue;
            }
            let after_remove = buffer.len() - to_remove;
            println!("SMB(2) message of len {} found", len);
            buffer.truncate_front(after_remove);
        } else {
            println!("Error decoding netbios header.");
            return;
        }
    }
}

fn main() {
    run();
}

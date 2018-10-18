#[macro_use]
extern crate nom;
#[macro_use]
extern crate bitflags;
extern crate byteorder;
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
        if buffer.len() < parser::TCP_TRANSPORT_LEN {
            continue;
        }

        let mut after_remove;

        {
            let body = parser::transport_segment(&buffer);

            if body.is_none() {
                println!("Error decoding netbios header.");
                return;
            }

            let body = body.unwrap();
            after_remove = buffer.len() - (body.len() + parser::TCP_TRANSPORT_LEN);
            println!("SMB(2) message of len {} found", body.len());
            let header = parser::messages(body, parser::Dialect::Smb3_0_2);
            match header {
                Ok(o) => println!("{:?}", o),
                _ => panic!("Invalid packets found.")
            }
        }

        if after_remove > 0 {
            buffer.truncate_front(after_remove);
        }
    }
}

fn main() {
    run();
}

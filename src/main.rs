extern crate ether;

use ether::packet::datalink::ethernet;
use ether::packet::datalink::ethernet::EtherType::IPv4;
use ether::packet::network::ipv4;
use ether::packet::network::ipv4::Protocol::TCP;
use ether::packet::transport::tcp;
use ether::pcap;

fn run() {
    use std::fs::File;

    let file = File::open("capture.pcap").unwrap();

    let pcap = pcap::PacketCapture::new(file);
    let (_, records) = pcap.parse().unwrap();
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
        println!("smb packet with payload: {:?}", segment.payload());
    }
}

fn main() {
    run();
}

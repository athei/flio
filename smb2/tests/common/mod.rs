use ether::packet::datalink::ethernet;
use ether::packet::datalink::ethernet::EtherType::IPv4;
use ether::packet::network::ipv4;
use ether::packet::network::ipv4::Protocol::TCP;
use ether::packet::transport::tcp;
use ether::pcap;
use std::path::Path;
use smb2::{ Request, V1Request };

pub enum CombinedRequest<'a> {
	V1(V1Request),
	V2(Request<'a>)
}

pub struct RequestList<'a> {
    pub requests: Vec<CombinedRequest<'a>>,
}

pub fn parse_pcap<'a>(path: &Path, buffer: &'a mut Vec<u8>) -> Result<RequestList<'a>, ()> {
    use std::fs::File;

    let file = File::open(path).unwrap();
    let pcap = pcap::PacketCapture::new(file);
    let (_, records) = pcap.parse().unwrap();
    let mut requests = Vec::new();

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
        if segment.payload().is_empty() {
            continue;
        }

        buffer.extend_from_slice(segment.payload());
    };

    let mut ptr = buffer.as_slice();

    while !ptr.is_empty() {
        match smb2::parse_request(ptr, smb2::Dialect::Smb3_0_2) {
            Ok((remaining, messages)) => {
                println!("{:?}", messages);
                ptr = &ptr[ptr.len() - remaining.len()..];
                for msg in messages {
                    requests.push(CombinedRequest::V2(msg));
                }
            },
            _ => {
                match smb2::parse_smb1_nego_request(&ptr) {
                    Ok((remaining, msg)) => {
                        println!("{:?}", msg);
                        ptr = &ptr[ptr.len() - remaining.len()..];
                        requests.push(CombinedRequest::V1(msg));
                    },
                    Err(err) => {
                        println!("{:?}", err);
                        return Err(()); 
                    }
                }
            }
        };
    }

    Ok(RequestList { requests })
}
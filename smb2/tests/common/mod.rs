use ether::packet::datalink::ethernet;
use ether::packet::datalink::ethernet::EtherType::IPv4;
use ether::packet::network::ipv4;
use ether::packet::network::ipv4::Protocol::TCP;
use ether::packet::transport::tcp;
use ether::pcap;
use std::path::Path;
use std::net::Ipv4Addr;
use nom::Err;
use smb2::{ Request, V1Request };

enum CombinedRequest<'a> {
	v1Request(V1Request),
	v2Request(Request<'a>)
}

struct RequestList<'a> {
    requests: Vec<CombinedRequest<'a>>,
    underlying_buffer: Vec<u8>
}

fn parse_pcap(path: &Path) -> Result<RequestList, ()> {
    use std::fs::File;

    let file = File::open(path).unwrap();
    let pcap = pcap::PacketCapture::new(file);
    let (_, records) = pcap.parse().unwrap();
    let mut buffer = Vec::new();
    let mut result = Vec::new();

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
        if packet.source() != Ipv4Addr::new(192, 168, 178, 20) {
            continue;
        }

        buffer.extend_from_slice(segment.payload());
    };

    let mut ptr = buffer.as_slice();

    while !ptr.is_empty() {
        match smb2::parse_request(ptr, smb2::Dialect::Smb3_0_2) {
            Ok((remaining, messages)) => {
                println!("{:?}", messages);
                ptr = &ptr[buffer.len() - remaining.len()..];
                for msg in messages {
                    result.push(CombinedRequest::v2Request(msg));
                }
            },
            _ => {
                match smb2::parse_smb1_nego_request(&buffer) {
                    Ok((remaining, msg)) => {
                        println!("{:?}", msg);
                        ptr = &ptr[buffer.len() - remaining.len()..];
                        result.push(CombinedRequest::v1Request(msg));
                    },
                    Err(err) => {
                        println!("{:?}", err);
                        return Err(()); 
                    }
                }
            }
        };
    }

    Ok(RequestList { requests: result, underlying_buffer: buffer })
}
use lazy_static::lazy_static;
use pcarp::Capture;
use pnet_packet::ethernet::{EtherTypes, EthernetPacket};
use pnet_packet::ipv4::Ipv4Packet;
use pnet_packet::ipv6::Ipv6Packet;
use pnet_packet::tcp::TcpPacket;
use pnet_packet::Packet;
use smb2::smb1::Request as V1Request;
use smb2::Request;
use std::path::PathBuf;

pub enum CombinedRequest<'a> {
    V1(V1Request),
    V2(Request<'a>),
}

#[allow(dead_code)]
impl<'a> CombinedRequest<'a> {
    pub fn unwrap_v1(&self) -> &V1Request {
        match self {
            CombinedRequest::V1(x) => x,
            _ => panic!("Request is not V1"),
        }
    }

    pub fn unwrap_v2(&self) -> &Request<'a> {
        match self {
            CombinedRequest::V2(x) => x,
            _ => panic!("Request is not V2"),
        }
    }
}

enum IPPacket<'a> {
    V4(Ipv4Packet<'a>),
    V6(Ipv6Packet<'a>),
}

lazy_static! {
    static ref test_dir: PathBuf = {
        let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        path.push("tests/data/");
        path
    };
}

fn get_payload<'a>(packet: &'a IPPacket<'a>) -> &'a [u8] {
    match packet {
        IPPacket::V4(p) => p.payload(),
        IPPacket::V6(p) => p.payload(),
    }
}

pub fn parse_pcap<'a>(name: &str, buffer: &'a mut Vec<u8>) -> Result<Vec<CombinedRequest<'a>>, ()> {
    use std::fs::File;

    let mut path: PathBuf = test_dir.clone();
    path.push(name);
    path.set_extension("pcapng");

    let file = File::open(path).unwrap();
    let mut pcap = Capture::new(file).unwrap();
    let mut requests = Vec::new();

    while let Some(record) = pcap.next() {
        let record = record.unwrap();
        let interface = record.interface.unwrap();

        /* smb packets must be contained in ethernet frames */
        assert_eq!(interface.link_type, pcarp::LinkType::ETHERNET);
        let eth_frame = EthernetPacket::new(record.data).unwrap();

        /* smb packets must use ipv4 or ipv6 */
        let ip_packet = match eth_frame.get_ethertype() {
            EtherTypes::Ipv4 => {
                let v4 = Ipv4Packet::new(eth_frame.payload()).unwrap();
                IPPacket::V4(v4)
            }
            EtherTypes::Ipv6 => {
                let v6 = Ipv6Packet::new(eth_frame.payload()).unwrap();
                IPPacket::V6(v6)
            }
            _ => panic!("All packets must be IPv4 or IPv6"),
        };
        let ip_payload = get_payload(&ip_packet);

        /* smb is transported in tcp port 445 */
        let tcp_segment = TcpPacket::new(ip_payload).unwrap();
        assert!(
            tcp_segment.get_source() == 445
                || tcp_segment.get_destination() == 445
                || tcp_segment.get_source() == 139
                || tcp_segment.get_destination() == 139
        );

        buffer.extend_from_slice(tcp_segment.payload());
    }

    let mut ptr = buffer.as_slice();

    while !ptr.is_empty() {
        match smb2::parse_request(ptr, smb2::Dialect::Smb3_0_2) {
            Ok((remaining, messages)) => {
                ptr = &ptr[ptr.len() - remaining.len()..];
                for msg in messages {
                    requests.push(CombinedRequest::V2(msg));
                }
            }
            _ => match smb2::parse_smb1_nego_request(&ptr) {
                Ok((remaining, msg)) => {
                    ptr = &ptr[ptr.len() - remaining.len()..];
                    requests.push(CombinedRequest::V1(msg));
                }
                _ => {
                    return Err(());
                }
            },
        };
    }

    Ok(requests)
}

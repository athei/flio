use lazy_static::lazy_static;
use nom::IResult;
use pcarp::Capture;
use pnet_packet::ethernet::{EtherTypes, EthernetPacket};
use pnet_packet::ipv4::Ipv4Packet;
use pnet_packet::ipv6::Ipv6Packet;
use pnet_packet::tcp::TcpPacket;
use pnet_packet::Packet;
use smb2_packet::smb1::NegotiateRequest as V1NegotRequest;
use smb2_packet::{parse, parse_smb1_nego_request, Dialect, Request, Response};
use std::path::PathBuf;

enum IPPacket<'a> {
    V4(Ipv4Packet<'a>),
    V6(Ipv6Packet<'a>),
}

lazy_static! {
    static ref TEST_DIR: PathBuf = {
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

fn response(data: &[u8], dialect: Dialect) -> IResult<&[u8], Vec<Response>> {
    parse::<Response>(data, dialect)
}

fn request(data: &[u8], dialect: Dialect) -> IResult<&[u8], Vec<Request>> {
    parse::<Request>(data, dialect)
}

fn request_smb1_nego(data: &[u8]) -> IResult<&[u8], Vec<V1NegotRequest>> {
    parse_smb1_nego_request(data).map(|(remaining, msg)| (remaining, vec![msg]))
}

pub fn parse_pcap_responses<'a>(
    name: &str,
    buffer: &'a mut Vec<u8>,
    dialect: Dialect,
) -> Result<Vec<Response<'a>>, String> {
    parse_pcap(name, buffer, |data| response(data, dialect))
}

pub fn parse_pcap_requests<'a>(
    name: &str,
    buffer: &'a mut Vec<u8>,
    dialect: Dialect,
) -> Result<Vec<Request<'a>>, String> {
    parse_pcap(name, buffer, |data| request(data, dialect))
}

pub fn parse_pcap_smb1nego(
    name: &str,
    buffer: &mut Vec<u8>,
) -> Result<Vec<V1NegotRequest>, String> {
    parse_pcap(name, buffer, request_smb1_nego)
}

fn parse_pcap<'a, F, T>(name: &str, buffer: &'a mut Vec<u8>, func: F) -> Result<Vec<T>, String>
where
    F: Fn(&'a [u8]) -> IResult<&'a [u8], Vec<T>>,
{
    use std::fs::File;

    let mut path: PathBuf = TEST_DIR.clone();
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
    let mut at_byte: usize = 0;
    while !ptr.is_empty() {
        match func(ptr) {
            Ok((remaining, mut messages)) => {
                let bytes_read = ptr.len() - remaining.len();
                ptr = &ptr[bytes_read..];
                requests.append(&mut messages);
                at_byte += bytes_read;
            }
            Err(err) => {
                let msg = format!(
                    "Error parsing at byte 0x{:08X} with value 0x{:02X}: {:x?}",
                    at_byte, ptr[0], err,
                );
                return Err(msg);
            }
        }
    }
    Ok(requests)
}

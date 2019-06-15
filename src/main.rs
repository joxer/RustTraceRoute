extern crate pnet;

use pnet::datalink::{self, NetworkInterface};
use pnet::packet::ipv4::{MutableIpv4Packet};
use pnet::packet::icmp::echo_request::MutableEchoRequestPacket;
use pnet::packet::icmp::echo_request;
use pnet::packet::icmp::IcmpTypes;
use std::net::{Ipv4Addr, ToSocketAddrs, SocketAddr, IpAddr};
use pnet::transport::{icmp_packet_iter, transport_channel, TransportChannelType::Layer3};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::MutablePacket;
use pnet::util;
use std::net;
use std::str::FromStr;
use std::process;
use std::env;
const IPV4_HEADER_LEN: usize = 21;
const ICMP_HEADER_LEN: usize = 8;
const ICMP_PAYLOAD_LEN: usize = 32;

fn create_ipv4_packet<'a>(ttl: u8, destination: Ipv4Addr, buffer: &'a mut [u8], buffer_icmp: &'a mut[u8])-> Result<pnet::packet::ipv4::MutableIpv4Packet<'a>, &'a str> {
    let mut ipv4_packet = pnet::packet::ipv4::MutableIpv4Packet::new(buffer).unwrap();
    ipv4_packet.set_version(4);
    ipv4_packet.set_header_length(IPV4_HEADER_LEN as u8);
    ipv4_packet.set_total_length((IPV4_HEADER_LEN + ICMP_HEADER_LEN + ICMP_PAYLOAD_LEN) as u16);
    ipv4_packet.set_ttl(ttl);
    ipv4_packet.set_next_level_protocol(IpNextHeaderProtocols::Icmp);
    ipv4_packet.set_destination(destination);
            
    let mut icmp_packet = MutableEchoRequestPacket::new(buffer_icmp).unwrap();
    icmp_packet.set_icmp_type(IcmpTypes::EchoRequest);
    
    let checksum = util::checksum(&icmp_packet.packet_mut(), 2);
    icmp_packet.set_checksum(checksum);
    ipv4_packet.set_payload(&icmp_packet.packet_mut());
    Ok(ipv4_packet)
}

fn main() {
    ::std::process::exit(match run_app() {
        Ok(_) => 0,
        Err(err) => {
            eprintln!("error: {:?}", err);
            1
        }
    });
}
fn run_app() -> std::result::Result<(), String> {

    let args: Vec<String> = std::env::args().collect();
    match args.len() {
        2 => {
            traceroute(&args[1]);
        }
        _ => {
            return Err("error in matching arguments".to_string());
        }

    }
    Ok(())
}
fn traceroute(addr: &String) -> std::result::Result<(), ()> {
    
    let protocol = Layer3(IpNextHeaderProtocols::Icmp);
    let (mut tx, mut rx) = transport_channel(1024, protocol)
        .map_err(|err| format!("Error opening the channel: {}", err)).unwrap();
    let mut rx = icmp_packet_iter(&mut rx);
        
    let to = net::Ipv4Addr::from_str(addr).map_err(|_| "Invalid address").unwrap();;
    let mut ttl = 1;

    let mut prev = to.clone();
    while ttl < 32 {
        let mut buffer=  [0u8; 40];
        let mut buffer_icmp =  [0u8; 40];
        let packet = create_ipv4_packet(ttl, to, &mut buffer, &mut buffer_icmp).unwrap();
        tx.send_to(packet, IpAddr::V4(to));
        if let Ok((_, addr)) = rx.next() {
            if addr == prev {
                return Ok(());
            }
            else{
                println!("TTL: {}, {}", ttl, addr);
                prev = Ipv4Addr::from_str(&addr.to_string()).unwrap();
            }
        }       
        
        ttl +=1;
    }    
    Ok(())
}

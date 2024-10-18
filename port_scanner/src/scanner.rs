use std::net::{TcpStream, Ipv4Addr, ToSocketAddrs};
use std::process;
use std::time::Duration;

const TIMEOUT: Duration = Duration::from_millis(500);

pub fn scan_tcp_ports(previous: u32, current: u32, host: &str) -> Vec<u32> {

    //Check if the provided ip is actually a valid IPv4 address
    if !host.parse::<Ipv4Addr>().is_ok() {
        println!("[!] Not a valid IPv4 address");
        process::exit(1);
    }

    let mut opened_ports: Vec<u32> = Vec::new();

    for port in previous..current {
        let sock: String = format!("{}:{}", host, port);
        match TcpStream::connect_timeout(&sock.to_socket_addrs().unwrap().next().unwrap(), TIMEOUT) {
            Ok(_) => {
                opened_ports.push(port);
            },
            Err(_e) => {}
        }
    }
    return opened_ports;
}
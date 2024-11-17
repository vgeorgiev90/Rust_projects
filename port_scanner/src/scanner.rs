use surge_ping::{Client, PingIdentifier, PingSequence};
use std::process;
use rand::random;
use tokio::net::TcpStream;
use tokio::time::{timeout, Duration};
use std::net::{Ipv4Addr, ToSocketAddrs, IpAddr};



const TIMEOUT: Duration = Duration::from_millis(500);



pub async fn scan_tcp_ports(previous: u32, current: u32, host: &str) -> Vec<u32> {
    if !host.parse::<Ipv4Addr>().is_ok() {
        println!("[!] Not a valid IPv4 address");
        process::exit(1);
    }

    let mut opened_ports = Vec::new();
    for port in previous..current {
        let sock: String = format!("{}:{}", host, port);
        let addr = sock.to_socket_addrs().unwrap().next().unwrap();

        match timeout(TIMEOUT, TcpStream::connect(addr)).await {
            Ok(Ok(_)) => {
                opened_ports.push(port);
            },
            Ok(Err(e)) => {
                if e.kind() == std::io::ErrorKind::ConnectionRefused {
                    // Closed port, no issue.
                } else if e.kind() == std::io::ErrorKind::Other && e.to_string().contains("No route to host") {
                    // Dead host, no point in scanning the whole range
                    return opened_ports;
                }
            },
            Err(_) => {
                // Timeout occurred.
            }
        }
    }
    return opened_ports;
}



pub async fn ping_sweep(client: Client, hosts: Vec<String>) -> Option<Vec<String>> {
    
    let mut live_hosts: Vec<String> = Vec::new();

    for host in hosts {
        let target = IpAddr::V4(host.parse::<Ipv4Addr>().unwrap());

        let payload = [0; 56];
        let mut ping_client = client.pinger(target, PingIdentifier(random())).await;
        ping_client.timeout(std::time::Duration::from_secs(1));

        match ping_client.ping(PingSequence(1), &payload).await {
            Ok(_) => {
                live_hosts.push(host);
            },
            Err(_e) => {
                //Host is down   
            }
        }
    }

    if !live_hosts.is_empty() {
        return Some(live_hosts);
    } else {
        return None;
    }
}
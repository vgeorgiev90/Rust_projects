use std::process;
use ipnetwork::IpNetwork;
use std::str::FromStr;
use colored::*;


//Split the given port range to equal sections
pub fn split_range(port_range: u32, threads: u32) -> Vec<u32> {
    let result = port_range / threads;
    let remain = port_range % threads;

    let mut ranges: Vec<u32> = Vec::new();
    let mut total: u32 = 0;
    for _ in 0..threads {
        total = total + result;
        ranges.push(total);
    }
    if remain > 0 {
        ranges.push(total+remain);
    }
    return ranges;
}


//Parse provided subnet and return a vector of hosts
pub fn parse_hosts(net: &str) -> Vec<String> {
    match IpNetwork::from_str(net) {
        Ok(network) => {
            let ips: Vec<String> = network.iter().map(|ip| ip.to_string()).collect();
            return ips;
        }
        Err(e) => {
            println!("Failed to parse CIDR: {}", e.to_string().red());
            process::exit(1);
        }
    }
}
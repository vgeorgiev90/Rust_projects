mod scanner;
mod utils;
use std::thread;
use std::sync::mpsc;
extern crate argparse;
use argparse::{ArgumentParser, Store};
use std::time::Instant;
use colored::*;

/*
TODO
1. Add option for UDP scan
2. Possibly try to grab a banner if it exist
*/

fn main() {

    let mut threads_arg: String = "".to_string();
    let mut hosts: String = "".to_string();
    let mut range_arg: String = "".to_string();

    //Argument parser
    {
        let mut ap = ArgumentParser::new();
        ap.set_description("Simple multi-threaded TCP port scanner based in rust");
        ap.refer(&mut hosts)
            .add_option(&["-r", "--host"], Store, "Host to scan, this should be a valid IPv4, or a CIDR range");
        ap.refer(&mut range_arg)
            .add_option(&["-p", "--port-range"], Store, "Port range to scan, eg: 1000 to scan from 1-1000");
        ap.refer(&mut threads_arg)
            .add_option(&["-t", "--threads"], Store, "Number of threads to run the scan with");
        ap.parse_args_or_exit();
    }

    //If there are no args passed exit
    if range_arg.is_empty() || hosts.is_empty() || threads_arg.is_empty() {
        println!("{}\n./port_scanner -h to see available options", "[!] No arguments passed".red());
        return;
    }

    //Parse the port range and threads as u32
    let range: u32 = match range_arg.parse::<u32>() {
        Ok(range) => range,
        Err(_e) => {
            println!("{}", "[!] Please provide a valid port range".red());
            return;
        }
    };
    let threads: u32 = match threads_arg.parse::<u32>() {
        Ok(thrads) => thrads,
        Err(_e) => {
            println!("{}", "[!] Please provide a valid integer for number of threads".red());
            return;
        }
    };

    //Parse the range to scan
    let range_to_scan: Vec<String> = utils::parse_hosts(hosts.as_str());

    println!("[+] Total hosts to scan: {}", range_to_scan.len().to_string().yellow());
    println!("[+] Scheduling {} ports scan to {} threads\n", range.to_string().yellow(), threads.to_string().yellow());

    //Loop trough all hosts and do a port scan
    for host in range_to_scan {
        let start = Instant::now();

        //Channel for thread communication
        let (sender, receiver) = mpsc::channel();
        //Vector to store opened ports
        let mut opened_ports: Vec<Vec<u32>> = Vec::new();
        //Vector to store thread handles
        let mut handles = Vec::new();

        println!("[+] Starting port scan for host: {}", host.blue());

        //Split the port range in equal parts
        let range_parts: Vec<u32> = utils::split_range(range, threads);

        for i in 0..range_parts.len() {
        
            //Clone the variables so they can be accessible in every iteration of the loop
            let current = range_parts[i];
            let previous = if i == 0 { 1 } else { range_parts[i - 1] }; // scan from previous to current
            let sender_clone = sender.clone();
            let host_clone = host.clone();
            //println!("[+] Scheduling thread {} for range: {}-{}", i, previous, current);

            let handle = thread::spawn(move || {
                let ports: Vec<u32> = scanner::scan_tcp_ports(previous, current, host_clone.as_str());
            
                //If there are open ports send them to the main thread
                if !ports.is_empty() {
                    sender_clone.send(ports).expect("[!] Cant send open ports to main");
                }
            });

            //push the handle to the handles vector
            handles.push(handle);
        }
        
        //Drop the sender after all threads are shceduled to prevent deadlocks in the receiver
        drop(sender);

        //Receive until there are no more senders
        while let Ok(data) = receiver.recv() {
            opened_ports.push(data);
        }

        //Wait for thread completion
        for hand in handles {
            hand.join().expect("[!] Thread panicked...");
        }

        //Measure how much time each scan took.
        let duration = start.elapsed();

        if !opened_ports.is_empty() {
            //Concat all vectors, transform the elements to string and finally join them as a single string
            println!("[+] Scan duration: {:.2}s", duration.as_secs_f64());
            println!("[+] Opened ports: \n\n{}\n", opened_ports.concat().iter().map(|port| port.to_string()).collect::<Vec<String>>().join(", ").green());
        } else {
            println!("[+] {}, most likely the host is not live\n", "No open ports".red());
        }
    }
}
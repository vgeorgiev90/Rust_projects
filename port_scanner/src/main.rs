mod scanner;
mod utils;
use tokio::sync::mpsc;
use tokio::task;
use surge_ping::{Client, Config};
extern crate argparse;
use argparse::{ArgumentParser, Store, StoreTrue};
use std::time::Instant;
use colored::*;

/*
TODO
1. Add option for UDP scan
2. Possibly try to grab a banner if it exist
*/

//#[tokio::main]
#[tokio::main(flavor = "multi_thread", worker_threads = 8)]
async fn main() {

    let mut threads_arg: String = "30".to_string();
    let mut hosts: String = "".to_string();
    let mut range_arg: String = "".to_string();
    let mut no_ping: bool = false;

    //Argument parser
    {
        let mut ap = ArgumentParser::new();
        ap.set_description("Simple multi-threaded TCP port scanner based in rust");
        ap.refer(&mut hosts)
            .add_option(&["-r", "--host"], Store, "Host to scan, this should be a valid IPv4, or a CIDR range");
        ap.refer(&mut range_arg)
            .add_option(&["-p", "--port-range"], Store, "Port range to scan, eg: 1000 to scan from 1-1000");
        ap.refer(&mut threads_arg)
            .add_option(&["-t", "--threads"], Store, "Number of threads to run the scan with, default: 30");
        ap.refer(&mut no_ping)
            .add_option(&["-n", "--no-ping"], StoreTrue, "Dont make a ping sweep to determine live hosts");
        ap.parse_args_or_exit();
    }

    //If there are no args passed exit
    if range_arg.is_empty() || hosts.is_empty() {
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
    let mut range_to_scan: Vec<String> = utils::parse_hosts(hosts.as_str());


    // Ping discovery
    let mut live_hosts: Vec<String> = Vec::new();
    if !no_ping {

        println!("[+] Doing ping sweep on target: {}", hosts.blue());
        //let (sender, mut receiver) = mpsc::unbounded_channel();
        let (sender, mut receiver) = mpsc::channel(2000);

        let chunk_size = (range_to_scan.len() + (threads as usize) - 1) / threads as usize;
        let host_parts: Vec<Vec<String>> = range_to_scan.chunks(chunk_size).map(|c| c.to_vec()).collect();
        let client_v4 = Client::new(&Config::default()).expect("[!] Could not create ICMP client");

        let mut ping_tasks = Vec::new();
        for part in host_parts {

            let sender_clone = sender.clone();
            let client_clone = client_v4.clone();
    
            let pinger = task::spawn(async move {
                match scanner::ping_sweep(client_clone, part).await {
                    Some(live_host) => sender_clone.send(live_host).await.unwrap(),
                    None => {}
                };
            });
    
            ping_tasks.push(pinger);
        }
        drop(sender);
    
        while let Some(data) = receiver.recv().await {
            live_hosts.extend(data);
        }
        // Wait for all tasks to finish
        for task in ping_tasks {
            task.await.unwrap();
        }
        range_to_scan = live_hosts;
    }


    println!("[+] Total hosts to scan: {}", range_to_scan.len().to_string().yellow());
    println!("[+] Scanning {} ports with {} threads\n", range.to_string().yellow(), threads.to_string().yellow());
    //Loop trough all hosts and do a port scan
    for host in range_to_scan {
        let start = Instant::now();

        //Channel for thread communication
        //let (sender, mut receiver) = mpsc::unbounded_channel();
        let (sender, mut receiver) = mpsc::channel(2000);

        //Vector to store opened ports
        let mut opened_ports: Vec<Vec<u32>> = Vec::new();
        //Vector to store thread handles
        let mut tasks = Vec::new();

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

            let scan_task = task::spawn(async move {
                let ports: Vec<u32> = scanner::scan_tcp_ports(previous, current, host_clone.as_str()).await;
            
                //If there are open ports send them to the main thread
                if !ports.is_empty() {
                    sender_clone.send(ports).await.expect("[!] Cant send open ports to main");
                }
            });

            //push the handle to the handles vector
            tasks.push(scan_task);
        }
        
        //Drop the sender after all threads are shceduled to prevent deadlocks in the receiver
        drop(sender);

        //Receive until there are no more senders
        while let Some(data) = receiver.recv().await {
            opened_ports.push(data);
        }

        //Wait for thread completion
        for task in tasks {
            task.await.unwrap();
        }

        //Measure how much time each scan took.
        let duration = start.elapsed();

        if !opened_ports.is_empty() {
            //Concat all vectors, transform the elements to string and finally join them as a single string
            println!("[+] Scan duration: {:.2}s", duration.as_secs_f64());
            println!("[+] Opened ports: \n\n{}\n", opened_ports.concat().iter().map(|port| port.to_string()).collect::<Vec<String>>().join(", ").green());
        } else {
            println!("[+] {}, the host is not live, or connect attempts are being filtered.\n", "No open ports".red());
        }
    }
}
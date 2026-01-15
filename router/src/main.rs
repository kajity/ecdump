// Copyright (c) 2023 t13801206 <https://zenn.dev/t13801206>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

mod arp;
mod packetdump;

use pnet::datalink::Channel::Ethernet;
use pnet::datalink::{MacAddr, NetworkInterface};
use pnet::packet::arp::ArpPacket;
use pnet::packet::ethernet::MutableEthernetPacket;
use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use pnet::packet::Packet;
use pnet::packet::ipv4::Ipv4Packet;
use std::collections::HashMap;
use std::env;
use std::net::Ipv4Addr;
use std::process;
use std::sync::{Arc, Mutex};
use std::{thread, time};

fn main() {
    let mut args = env::args().skip(1);

    let iface_name0 = match args.next() {
        Some(n) => n,
        None => {
            eprintln!("USAGE: router-rs <NETWORK INTERFACE 1> <NETWORK INTERFACE 2>");
            process::exit(1);
        }
    };

    let iface_name1 = match args.next() {
        Some(n) => n,
        None => {
            eprintln!("USAGE: router-rs <NETWORK INTERFACE 1> <NETWORK INTERFACE 2>");
            process::exit(1);
        }
    };

    let interface0 = Arc::new(
        pnet::datalink::interfaces()
            .into_iter()
            .find(|iface| iface.name == iface_name0)
            .unwrap(),
    );

    let interface1 = Arc::new(
        pnet::datalink::interfaces()
            .into_iter()
            .find(|iface| iface.name == iface_name1)
            .unwrap(),
    );

    let mut threads = vec![];
    let atbl = Arc::new(Mutex::new(HashMap::<Ipv4Addr, MacAddr>::new()));

    let (mut tx0, mut rx0) = match pnet::datalink::channel(&interface0, Default::default()) {
        Ok(Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("packetdump: unhandled channel type"),
        Err(e) => panic!("packetdump: unable to create channel: {}", e),
    };

    let (mut tx1, mut rx1) = match pnet::datalink::channel(&interface1, Default::default()) {
        Ok(Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("packetdump: unhandled channel type"),
        Err(e) => panic!("packetdump: unable to create channel: {}", e),
    };

    let thread = std::thread::Builder::new()
        .name(format!("thread{}", 1))
        .spawn({
            let itf0 = Arc::clone(&interface0);
            let itf1 = Arc::clone(&interface1);
            let atbl = Arc::clone(&atbl);

            move || loop {
                match rx0.next() {
                    Ok(packet_in) => {
                        receive_process(1, packet_in, &itf0, &itf1, &atbl, &mut tx1);
                    }
                    Err(e) => panic!("packetdump: unable to receive packet: {}", e),
                }
            }
        });

    threads.push(thread.unwrap());

    let thread = std::thread::Builder::new()
        .name(format!("thread{}", 2))
        .spawn({
            let itf0 = Arc::clone(&interface0);
            let itf1 = Arc::clone(&interface1);
            let atbl = Arc::clone(&atbl);

            move || loop {
                match rx1.next() {
                    Ok(packet_in) => {
                        receive_process(2, packet_in, &itf1, &itf0, &atbl, &mut tx0);
                    }
                    Err(e) => panic!("packetdump: unable to receive packet: {}", e),
                }
            }
        });

    threads.push(thread.unwrap());

    for t in threads {
        t.join().unwrap();
    }
}

fn update_arp_table(
    packet: &[u8],
    interface: &NetworkInterface,
    atbl: &Arc<Mutex<HashMap<Ipv4Addr, MacAddr>>>,
) {
    let arp = ArpPacket::new(&packet[MutableEthernetPacket::minimum_packet_size()..]).unwrap();
    if arp.get_target_hw_addr() == interface.mac.unwrap() {
        atbl.lock()
            .unwrap()
            .insert(arp.get_sender_proto_addr(), arp.get_sender_hw_addr());
        println!(
            "[update_arp_table] (sender)ip:{}, (sender)mac:{}",
            arp.get_sender_proto_addr(),
            arp.get_sender_hw_addr()
        );
    }
}

fn receive_process(
    id: u8,
    packet_in: &[u8],
    itf0: &NetworkInterface,
    itf1: &NetworkInterface,
    atbl: &Arc<Mutex<HashMap<Ipv4Addr, MacAddr>>>,
    tx: &mut Box<dyn pnet::datalink::DataLinkSender>,
) {
    println!("[{}] packet in", id);
    let ethernet = EthernetPacket::new(packet_in).unwrap();

    packetdump::handle_ethernet_frame(itf0, &ethernet);

    if ethernet.get_ethertype() == EtherTypes::Arp {
        println!("[{}] receive ARP packet", id);
        update_arp_table(packet_in, itf0, atbl);
        return;
    } else {
        println!("[{}] transport packet", id);
    }

    let ip_packet = Ipv4Packet::new(ethernet.payload()).unwrap();
    let target_ip = ip_packet.get_destination();

    if atbl.lock().unwrap().get(&target_ip).is_none() {
        println!("[{}] {} not found in ARP table", id, target_ip);
        let arp_request = arp::gen_arp_request(itf1, target_ip);
        tx.send_to(&arp_request, None);
        println!("[{}] sent ARP request", id);
    }

    for retry_count in 1..6 {
        let atbl_lock = atbl.lock().unwrap();

        if let Some(t) = atbl_lock.get(&target_ip) {
            println!("[{}] Target MAC address: {}", id, t);
            let m = &itf1.mac.unwrap();
            let mut v = vec![t.0, t.1, t.2, t.3, t.4, t.5, m.0, m.1, m.2, m.3, m.4, m.5];
            v.extend(&packet_in[12..]);

            println!("[{}] send packet", id);
            tx.send_to(&v, None);

            break;
        } else {
            drop(atbl_lock);
            thread::sleep(time::Duration::from_millis(10));
            println!(
                "[{}] waiting for ARP resolution ...retry:{}",
                id, retry_count
            );
            continue;
        }
    }
}

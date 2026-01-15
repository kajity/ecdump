mod packet_source;
mod startup;

use bytes::BytesMut;
use ecdump::packetdump;
use packet_source::{InterfaceError, PcapSource};

use log::{debug, error, info, warn};
use pcap_file::{pcap, pcapng, pcapng::Block as PcapNgBlock};
use pnet::datalink::Channel::Ethernet;
use pnet::packet::Packet;
use pnet::packet::ethernet::EthernetPacket;
use std::fs::File;

use crate::packet_source::CapturedData;

fn main() {
    let config = startup::parse_args();
    startup::set_up_logging(config.verbose);

    let (tx_buffer, rx_buffer) = match config.pcap_source {
        PcapSource::File(file) => {
            let file_in = match File::open(&file.file_path) {
                Ok(f) => f,
                Err(e) => {
                    error!("Failed to open file '{}': {}", file.file_path, e);
                    std::process::exit(1);
                }
            };

            packet_source::start_read_pcap(file_in, file.is_pcapng)
        }

        PcapSource::Interface(interface) => {
            let interface = match packet_source::get_interface(interface) {
                Ok(iface) => iface,
                Err(e) => {
                    match e {
                        InterfaceError::NotFound(ifname) => {
                            error!("Network interface not found: {}", ifname);
                        }
                        InterfaceError::DefaultError(err_msg) => {
                            error!("Failed to get default interface: {}", err_msg);
                        }
                    }
                    println!("\x1b[33mAvailable network interfaces:\x1b[0m");
                    pnet::datalink::interfaces().into_iter().for_each(|iface| {
                        println!("  - {}: {}", iface.name, iface.description);
                    });

                    std::process::exit(1);
                }
            };

            debug!("Using network interface: {}", interface.name);
            let (tx_buffer, rx_buffer) = match packet_source::start_packet_receive(interface) {
                Ok(receiver) => receiver,
                Err(e) => {
                    error!("Failed to start packet receiving: {}", e);
                    std::process::exit(1);
                }
            };
            (tx_buffer, rx_buffer)
        }
    };

    let timestamp = std::time::Instant::now();
    loop {
        match rx_buffer.recv() {
            Ok(CapturedData { data: packet, .. }) => {
                let ethercat_packet = match packetdump::EtherCATPacket::new(packet.as_ref()) {
                    Some(pkt) => pkt,
                    None => {
                        warn!("Failed to parse EtherCAT packet");
                        continue;
                    }
                };
                info!(
                    "EtherCAT Packet - Length: {}, Type: {}",
                    ethercat_packet.datagram_length(),
                    ethercat_packet.protocol_type()
                );
                let ethercat_datagram =
                    match packetdump::EtherCATDatagram::new(ethercat_packet.payload()) {
                        Some(dg) => dg,
                        None => {
                            warn!("Failed to parse EtherCAT datagram");
                            continue;
                        }
                    };
                info!(
                    "EtherCAT Datagram - Command: {}({:02x}), Index: {}, Address: {:08x}, Length: {}",
                    ethercat_datagram.command_str(),
                    ethercat_datagram.command(),
                    ethercat_datagram.index(),
                    ethercat_datagram.address(),
                    ethercat_datagram.length(),
                );

                match BytesMut::try_from(packet) {
                    Ok(buf) => {
                        let _ = tx_buffer.send(buf);
                    }
                    Err(e) => {
                        warn!("Failed to convert packet to BytesMut: {}", e);
                    }
                }
            }
            Err(_) => {
                break;
            }
        }

        let _duration = timestamp.elapsed();
    }
}

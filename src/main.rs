mod analyzer;
mod logger;
mod packet_source;
mod startup;

use anyhow::{Context, Result, anyhow};
use bytes::BytesMut;
use console::style;
use ecdump::ec_packet;
use log::{debug, error, info, warn};
use netdev::net::device;
use packet_source::{CapturedData, PcapSource};
use std::fs::File;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

fn main() -> Result<()> {
    let config = startup::parse_args();

    if config.list_interfaces {
        println!("{}", style("Available network interfaces:").green());
        packet_source::get_interface_list()
            .into_iter()
            .for_each(|iface| {
                println!(
                    " | {} : {} [{}]",
                    iface.name,
                    iface.description,
                    iface.oper_state.as_str()
                );
            });
        return Ok(());
    }

    startup::set_up_logging(config.verbose);

    let m = indicatif::MultiProgress::new();

    let running_flag = Arc::new(AtomicBool::new(true));
    let r = running_flag.clone();

    let (handle, tx_buffer, rx_buffer) = match config.pcap_source {
        PcapSource::File(file) => {
            ctrlc::set_handler(move || {
                r.store(false, Ordering::SeqCst);
            })
            .expect("Error setting Ctrl-C handler");

            let file_in = File::open(&file.file_path)
                .with_context(|| format!("Failed to open pcap file: {}", &file.file_path))?;

            packet_source::start_read_pcap(file_in, file.is_pcapng, running_flag.clone())
        }

        PcapSource::Interface(interface) => {
            ctrlc::set_handler(move || {
                std::process::exit(0);
            })
            .expect("Error setting Ctrl-C handler");

            let interface = packet_source::get_interface(interface)
                .map_err(|e| anyhow!("{}", e))
                .with_context(
                    || "Failed to get network interface. Use -D to see available interfaces.",
                )?;

            debug!("Using network interface: {}", interface.name);
            packet_source::start_packet_receive(interface, running_flag.clone())?
        }
    };

    let mut device_manager = analyzer::DeviceManager::new();

    let timestamp = std::time::Instant::now();
    loop {
        match rx_buffer.recv() {
            Ok(CapturedData { data: packet, timestamp, from_main }) => {
                let ethercat_packet = match ec_packet::ECFrame::new(packet.as_ref()) {
                    Some(pkt) => pkt,
                    None => {
                        warn!("Failed to parse EtherCAT packet");
                        continue;
                    }
                };

                let _ = device_manager
                    .analyze_packet(&ethercat_packet, from_main)
                    .map_err(|e| error!("{:?}", e));

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

    if let Err(e) = handle.join() {
        error!("Packet source thread terminated with error: {:?}", e);
    }

    Ok(())
}

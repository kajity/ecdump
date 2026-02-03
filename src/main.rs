mod analyzer;
mod logger;
mod packet_source;
mod startup;

use anyhow::{Context, Result, anyhow, bail};
use bytes::BytesMut;
use console::style;
use crossbeam_channel::bounded;
use ecdump::ec_packet;
use log::{debug, error, warn};
use packet_source::{CapturedData, PcapSource};
use std::fs::File;
use std::io::BufWriter;
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

    startup::set_up_logging(config.debug);

    let running_flag = Arc::new(AtomicBool::new(true));
    let r = running_flag.clone();
    let file_out = match &config.output_file {
        Some(path) => {
            if let PcapSource::File(file_in) = &config.pcap_source {
                if file_in.file_path == *path {
                    bail!("Output file path must be different from input file path");
                }
            }
            let file_out = File::create(path)
                .with_context(|| format!("Failed to create output file: {}", path))?;
            Some(BufWriter::new(file_out))
        }
        None => None,
    };

    let (handle, tx_buffer, rx_buffer) = match config.pcap_source {
        PcapSource::File(file) => {
            ctrlc::set_handler(move || {
                r.store(false, Ordering::SeqCst);
            })
            .expect("Error setting Ctrl-C handler");

            let file_in = File::open(&file.file_path)
                .with_context(|| format!("Failed to open pcap file: {}", &file.file_path))?;

            packet_source::start_read_pcap(file_in, file_out, file.is_pcapng, running_flag.clone())
        }

        PcapSource::Interface(interface) => {
            let (abort_tx, abort_rx) = bounded::<bool>(0);
            ctrlc::set_handler(move || {
                abort_tx.send(true).ok();
                r.store(false, Ordering::SeqCst);
                std::thread::sleep(std::time::Duration::from_millis(200));
                std::process::exit(0);
            })
            .expect("Error setting Ctrl-C handler");

            let interface = packet_source::get_interface(interface)
                .map_err(|e| anyhow!("{}", e))
                .with_context(
                    || "Failed to get network interface. Use -D to see available interfaces.",
                )?;

            debug!("Using network interface: {}", interface.name);
            packet_source::start_packet_receive(interface, file_out, (running_flag.clone(), abort_rx))?
        }
    };

    let mut device_manager = analyzer::DeviceManager::new();

    let timestamp = std::time::Instant::now();
    loop {
        match rx_buffer.recv() {
            Ok(CapturedData {
                data: packet,
                timestamp,
                from_main,
            }) => {
                let ethercat_packet = match ec_packet::ECFrame::new(packet.as_ref()) {
                    Some(pkt) => pkt,
                    None => {
                        warn!("Failed to parse EtherCAT packet");
                        continue;
                    }
                };

                let _ = device_manager
                    .analyze_packet(&ethercat_packet, timestamp, from_main)
                    .map_err(|e| error!("{:?}", e));

                tx_buffer.send(BytesMut::from(packet)).ok();
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

mod analyzer;
mod logger;
mod packet_source;
mod startup;

use analyzer::ECError;
use anyhow::{Context, Result};
use bytes::BytesMut;
use console::style;
use crossbeam_channel::{bounded, select};
use ecdump::ec_packet;
use log::{debug, error, warn};
use packet_source::CapturedData;
use startup::PcapSource;
use std::fs::File;
use std::io::BufWriter;

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

    let (abort_tx, abort_rx) = bounded::<bool>(0);
    let file_out = match &config.output_file {
        Some(path) => {
            if let PcapSource::File(file_in) = &config.pcap_source {
                if file_in.file_path == *path {
                    anyhow::bail!("Output file path must be different from input file path");
                }
            }
            let file_out = File::create(path)
                .with_context(|| format!("Failed to create output file: {}", path))?;
            Some(BufWriter::new(file_out))
        }
        None => None,
    };

    let (handle, tx_buffer, rx_data) = match config.pcap_source {
        PcapSource::File(file) => {
            let (abort_tx2, abort_rx2) = bounded::<bool>(0);
            ctrlc::set_handler(move || {
                abort_tx2.send(true).ok();
                abort_tx.send(true).ok();
            })
            .expect("Error setting Ctrl-C handler");

            let file_in = File::open(&file.file_path)
                .with_context(|| format!("Failed to open pcap file: {}", &file.file_path))?;

            packet_source::start_read_pcap(file_in, file_out, file.is_pcapng, abort_rx2)
                .with_context(|| {
                    format!("Failed to start reading pcap file: {}", &file.file_path)
                })?
        }

        PcapSource::Interface(interface) => {
            let (abort_tx2, abort_rx2) = bounded::<bool>(0);
            ctrlc::set_handler(move || {
                abort_tx2.send(true).ok();
                abort_tx.send(true).ok();
            })
            .expect("Error setting Ctrl-C handler");

            let interface = packet_source::get_interface(interface).with_context(
                || "Failed to get network interface. Use -D to see available interfaces.",
            )?;

            debug!("Using network interface: {}", interface.name);
            packet_source::start_packet_receive(interface, file_out, abort_rx2)?
        }
    };

    let mut device_manager = analyzer::DeviceManager::new();

    loop {
        if abort_rx.try_recv().is_ok() {
            break;
        }

        select! {
            recv(abort_rx) -> _ => {
                break;
            }
            recv(rx_data) -> msg => {
                match msg {
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

                        let result = device_manager
                            .analyze_packet(&ethercat_packet, timestamp, from_main);

                        tx_buffer.send(BytesMut::from(packet)).ok();

                        if let Err(error) = result {
                            report_errors(error);
                        }

                    }
                    Err(_) => {
                        break;
                    }
                }
            }
        }
    }
    drop(rx_data);
    drop(tx_buffer);

    if let Some(handle) = handle {
        if let Err(e) = handle.join() {
            error!("Packet source thread terminated with error: {:?}", e);
        }
    }

    Ok(())
}

fn report_errors(error: ECError) {
    match error {
        ECError::DeviceError(errors) => {
            for err in errors {
                match err {
                    analyzer::ECDeviceError::InvalidWkc {
                        packet_number,
                        command,
                        from_main,
                        timestamp,
                        expected,
                        actual,
                    } => {
                        let direction = if from_main {
                            "Main -> Device"
                        } else {
                            "Device -> Main"
                        };
                    }
                    _ => {}
                }
            }
        }
        _ => {}
    }
}

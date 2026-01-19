use ecdump::ec_packet;
use ecdump::subdevice::ECStateMachine;

use core::time;

use fern::colors::{Color, ColoredLevelConfig};
use log::{debug, error, info, warn};
use netdev::interface::state;
use pnet::datalink::Channel::Ethernet;
use pnet::packet::Packet;
use pnet::packet::ethernet::EthernetPacket;

fn main() {
    let colors_line = ColoredLevelConfig::new()
        .error(Color::Red)
        .warn(Color::Yellow)
        .info(Color::Green)
        .debug(Color::Blue)
        .trace(Color::BrightBlack);

    let _ = fern::Dispatch::new()
        // Perform allocation-free log formatting
        .format(move |out, message, record| {
            out.finish(format_args!(
                "[{} {}] {}",
                chrono::Local::now().format("%H:%M:%S%.6f"),
                colors_line.color(record.level()),
                message
            ))
        })
        .level(log::LevelFilter::Debug)
        .level_for("hyper", log::LevelFilter::Info)
        .chain(std::io::stdout())
        .apply();

    let get_interfaces = || {
        println!("Available network interfaces:");
        let mut interface_str = String::new();
        pnet::datalink::interfaces().into_iter().for_each(|iface| {
            interface_str.push_str(&format!("  - {}: {}\n", iface.name, iface.description));
        });
        interface_str
    };
    let ifname = match std::env::args().nth(1) {
        Some(name) => name,
        None => {
            #[cfg(target_os = "windows")]
            let mut best_device_name = String::from("\\Device\\NPF_");
            #[cfg(not(target_os = "windows"))]
            let mut best_device_name = String::new();

            match netdev::get_default_interface() {
                Ok(dev) => {
                    debug!(
                        "Default network interface found: {}",
                        dev.friendly_name
                            .as_ref()
                            .unwrap_or(dev.description.as_ref().unwrap_or(&dev.name))
                    );
                    best_device_name.push_str(&dev.name);
                    best_device_name
                }
                Err(e) => {
                    error!(
                        "Failed to get default network interface: {}\n{}",
                        e,
                        get_interfaces()
                    );
                    std::process::exit(1);
                }
            }
        }
    };
    let interface = pnet::datalink::interfaces()
        .into_iter()
        .find(|iface| iface.name.contains(&ifname))
        .unwrap_or_else(|| {
            error!(
                "Network interface '{}' not found\n{}",
                ifname,
                get_interfaces()
            );
            std::process::exit(1);
        });
    info!("Using network interface: {}", interface.name);

    let (mut tx, mut rx) = match pnet::datalink::channel(&interface, Default::default()) {
        Ok(Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => {
            error!("Unhandled channel type");
            std::process::exit(1);
        }
        Err(e) => {
            error!("Unable to create channel: {}", e);
            std::process::exit(1);
        }
    };

    let mut ethercat_state_machine = ECStateMachine::new();
    let timestamp = std::time::Instant::now();
    loop {
        let mark_of_self = (7, 0x03);
        match rx.next() {
            Ok(packet) => {
                if packet[mark_of_self.0] == mark_of_self.1 {
                    // debug!("Ignoring packet starting with 0x03");
                    continue;
                }

                let ethernet = EthernetPacket::new(packet).unwrap();
                if ethernet.get_ethertype().0 != 0x88a4 {
                    continue;
                }
                info!(
                    "Received packet: {} > {}; length: {}",
                    ethernet.get_source(),
                    ethernet.get_destination(),
                    ethernet.packet().len(),
                );
                let ethercat_packet = match ec_packet::ECPacket::new(ethernet.payload()) {
                    Some(pkt) => pkt,
                    None => {
                        warn!("Failed to parse EtherCAT packet");
                        continue;
                    }
                };
                // info!(
                //     "EtherCAT Packet - Length: {}, Type: {}",
                //     ethercat_packet.datagram_length(),
                //     ethercat_packet.protocol_type()
                // );
                let ethercat_datagram =
                    match ec_packet::ECDatagram::new(ethercat_packet.payload()) {
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

                let mut return_packet = packet.to_vec();
                return_packet[mark_of_self.0] = mark_of_self.1;
                let mut ethercat_packet =
                    ec_packet::ECPacketView::new(&mut return_packet[14..]).unwrap();
                ethercat_state_machine.next(&mut ethercat_packet);
                // debug!("Response packet: {:02x?}", return_packet.as_slice());
                tx.send_to(return_packet.as_slice(), None);
            }
            Err(e) => {
                warn!("Failed to read packet: {}", e);
            }
        }

        let _duration = timestamp.elapsed();
    }
}

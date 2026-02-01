use anyhow::{Result, anyhow, bail};
use bytes::{BufMut, Bytes, BytesMut};
use log::error;
use netdev::prelude::OperState;
use pcap_file::{pcap, pcapng, pcapng::Block as PcapNgBlock};
use pnet::datalink::Channel::Ethernet;
use pnet::datalink::{Config, NetworkInterface};
use pnet::packet::Packet;
use pnet::packet::ethernet::EthernetPacket;
use pnet::util::MacAddr;
use std::fs::File;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, Sender};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};
pub struct PcapFileConfig {
    pub file_path: String,
    pub is_pcapng: bool,
}

pub struct CapturedData {
    pub timestamp: Duration,
    pub from_main: bool,
    pub data: Bytes,
}

pub enum PcapSource {
    Interface(Option<String>),
    File(PcapFileConfig),
}

pub struct NetworkInterfaceInfo {
    pub name: String,
    pub description: String,
    pub oper_state: OperState,
}

pub fn get_interface_list() -> Vec<NetworkInterfaceInfo> {
    let interfaces = pnet::datalink::interfaces(); // get list from pnet
    let interface_with_oper_state = netdev::get_interfaces();
    interfaces
        .into_iter()
        .map(|iface| {
            let oper_state = interface_with_oper_state
                .iter()
                .find(|i| i.index == iface.index)
                .map_or(OperState::Unknown, |i| i.oper_state);
            NetworkInterfaceInfo {
                name: iface.name,
                description: iface.description,
                oper_state,
            }
        })
        .collect()
}

pub fn get_interface(ifname: Option<String>) -> Result<NetworkInterface> {
    let ifname = match ifname {
        Some(name) => name,
        None => {
            #[cfg(target_os = "windows")]
            let mut best_device_name = String::from("\\Device\\NPF_");
            #[cfg(not(target_os = "windows"))]
            let mut best_device_name = String::new();

            let default_ifname = netdev::get_default_interface().map_err(|e| anyhow!("{}", e))?;
            best_device_name.push_str(&default_ifname.name);
            best_device_name
        }
    };
    let interface = pnet::datalink::interfaces()
        .into_iter()
        .find(|iface| iface.name.contains(&ifname))
        .ok_or_else(|| anyhow!("Network interface not found: {}", ifname.clone()))?;
    Ok(interface)
}

pub fn start_packet_receive(
    interface: NetworkInterface,
    running: Arc<AtomicBool>,
) -> Result<(JoinHandle<()>, Sender<BytesMut>, Receiver<CapturedData>)> {
    let config = Config {
        read_timeout: Some(Duration::from_millis(100)), // Linux/BPF/Netmap only
        ..Default::default()
    };
    let (_, mut datalink_rx) = match pnet::datalink::channel(&interface, config)? {
        Ethernet(tx, rx) => (tx, rx),
        _ => bail!("Unsupported channel type"),
    };

    let channel_size = 100;
    let (tx_data, rx_data) = mpsc::sync_channel(channel_size);
    let (tx_recycle, rx_recycle) = mpsc::channel();
    let handle = std::thread::spawn(move || {
        let timestamp = Instant::now();
        while running.load(Ordering::SeqCst) {
            match datalink_rx.next() {
                Ok(packet) => {
                    let packet = EthernetPacket::new(packet);
                    let ethercat_packet = match packet {
                        // Some(eth) if eth.get_ethertype().0 == 0x88a4 => eth,
                        Some(eth) => eth,
                        _ => continue,
                    };
                    let ethercat_packet = ethercat_packet.payload();

                    let mut buffer = match rx_recycle.try_recv() {
                        Ok(buf) => buf,
                        Err(_) => BytesMut::with_capacity(ethercat_packet.len()),
                    };
                    buffer.clear();
                    buffer.put_slice(ethercat_packet);
                    let ethercat_packet = buffer.freeze();
                    if tx_data
                        .send(CapturedData {
                            timestamp: timestamp.elapsed(),
                            from_main: false,
                            data: ethercat_packet,
                        })
                        .is_err()
                    {
                        break;
                    }
                }
                Err(e) => match e.kind() {
                    std::io::ErrorKind::TimedOut => continue,
                    _ => error!("An error occurred while reading: {}", e),
                },
            }
        }
    });

    Ok((handle, tx_recycle, rx_data))
}

pub fn start_read_pcap(
    pcap_file: File,
    is_pcapng: bool,
    running: Arc<AtomicBool>,
) -> (JoinHandle<()>, Sender<BytesMut>, Receiver<CapturedData>) {
    let channel_size = 0;
    let (tx_data, rx_data) = mpsc::sync_channel(channel_size);
    let (tx_recycle, rx_recycle) = mpsc::channel();

    let handle = if is_pcapng {
        std::thread::spawn(move || {
            let mut pcapng_reader = pcapng::PcapNgReader::new(pcap_file).expect("PCAPNG Reader");
            let mut initial_frame = true;
            let mut src_mac = MacAddr::zero();
            let mut initial_timestamp = Duration::from_secs(0);

            while running.load(Ordering::SeqCst)
                && let Some(Ok(block)) = pcapng_reader.next_block()
            {
                let (data, timestamp) = match block {
                    PcapNgBlock::EnhancedPacket(epb) => (epb.data, epb.timestamp),
                    PcapNgBlock::Packet(p) => (p.data, Duration::from_secs(p.timestamp)),
                    PcapNgBlock::SimplePacket(sp) => (sp.data, Duration::from_secs(0)),
                    _ => continue,
                };
                let ethernet = EthernetPacket::new(&data).expect("ethernet packet");
                if ethernet.get_ethertype().0 != 0x88a4 {
                    continue;
                }

                let from_main = if initial_frame {
                    src_mac = ethernet.get_source();
                    initial_frame = false;
                    initial_timestamp = timestamp;
                    true
                } else {
                    ethernet.get_source() == src_mac
                };

                let timestamp = timestamp - initial_timestamp;
                let ethercat_packet = ethernet.payload();
                let mut buffer = match rx_recycle.try_recv() {
                    Ok(buf) => buf,
                    Err(_) => BytesMut::with_capacity(ethercat_packet.len()),
                };
                buffer.clear();
                buffer.put_slice(ethercat_packet);
                let ethercat_packet = buffer.freeze();
                if tx_data
                    .send(CapturedData {
                        timestamp,
                        from_main,
                        data: ethercat_packet,
                    })
                    .is_err()
                {
                    break;
                }
            }
        })
    } else {
        std::thread::spawn(move || {
            let mut pcap_reader = pcap::PcapReader::new(pcap_file).expect("PCAP Reader");
            let mut initial_frame = true;
            let mut src_mac = MacAddr::zero();
            let mut initial_timestamp = Duration::from_secs(0);

            while running.load(Ordering::SeqCst)
                && let Some(Ok(packet)) = pcap_reader.next_packet()
            {
                let ethernet = EthernetPacket::new(&packet.data).expect("ethernet packet");
                if ethernet.get_ethertype().0 != 0x88a4 {
                    continue;
                }

                let from_main = if initial_frame {
                    src_mac = ethernet.get_source();
                    initial_frame = false;
                    initial_timestamp = packet.timestamp;
                    true
                } else {
                    ethernet.get_source() == src_mac
                };

                let timestamp = packet.timestamp - initial_timestamp;
                let ethercat_packet = ethernet.payload();
                let mut buffer = match rx_recycle.try_recv() {
                    Ok(buf) => buf,
                    Err(_) => BytesMut::with_capacity(ethercat_packet.len()),
                };
                buffer.clear();
                buffer.put_slice(ethercat_packet);
                let ethercat_packet = buffer.freeze();
                if tx_data
                    .send(CapturedData {
                        timestamp,
                        from_main,
                        data: ethercat_packet,
                    })
                    .is_err()
                {
                    error!("Failed to send captured data");
                    break;
                }
            }
        })
    };
    (handle, tx_recycle, rx_data)
}

use bytes::{BufMut, Bytes, BytesMut};
use core::time;
use log::error;
use pcap_file::{pcap, pcapng, pcapng::Block as PcapNgBlock};
use pnet::datalink::Channel::Ethernet;
use pnet::datalink::NetworkInterface;
use pnet::packet::Packet;
use pnet::packet::ethernet::EthernetPacket;
use std::error::Error;
use std::fs::File;
use std::sync::mpsc::{self, Receiver, Sender};
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

pub enum InterfaceError {
    NotFound(String),
    DefaultError(String),
}

pub fn get_interface(ifname: Option<String>) -> Result<NetworkInterface, InterfaceError> {
    let ifname = match ifname {
        Some(name) => name,
        None => {
            #[cfg(target_os = "windows")]
            let mut best_device_name = String::from("\\Device\\NPF_");
            #[cfg(not(target_os = "windows"))]
            let mut best_device_name = String::new();

            let default_ifname = netdev::get_default_interface()
                .map_err(|e| InterfaceError::DefaultError(e.to_string()))?;
            best_device_name.push_str(&default_ifname.name);
            best_device_name
        }
    };
    let interface = pnet::datalink::interfaces()
        .into_iter()
        .find(|iface| iface.name.contains(&ifname))
        .ok_or_else(|| InterfaceError::NotFound(ifname.clone()))?;
    Ok(interface)
}

pub fn start_packet_receive(
    interface: NetworkInterface,
) -> Result<(Sender<BytesMut>, Receiver<CapturedData>), Box<dyn Error>> {
    let (_, mut datalink_rx) = match pnet::datalink::channel(&interface, Default::default())? {
        Ethernet(tx, rx) => (tx, rx),
        _ => return Err("Unsupported channel type".into()),
    };

    let channel_size = 100;
    let (tx_data, rx_data) = mpsc::sync_channel(channel_size);
    let (tx_recycle, rx_recycle) = mpsc::channel();
    std::thread::spawn(move || {
        loop {
            let mut timestamp = Instant::now();
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
                    timestamp = Instant::now();
                }
                Err(e) => {
                    error!("An error occurred while reading: {}", e);
                }
            }
        }
    });

    Ok((tx_recycle, rx_data))
}

pub fn start_read_pcap(
    pcap_file: File,
    is_pcapng: bool,
) -> (Sender<BytesMut>, Receiver<CapturedData>) {
    let channel_size = 100;
    let (tx_data, rx_data) = mpsc::sync_channel(channel_size);
    let (tx_recycle, rx_recycle) = mpsc::channel();

    if is_pcapng {
        std::thread::spawn(move || {
            let mut pcapng_reader = pcapng::PcapNgReader::new(pcap_file).expect("PCAPNG Reader");

            while let Some(Ok(block)) = pcapng_reader.next_block() {
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
                        timestamp: timestamp,
                        from_main: false,
                        data: ethercat_packet,
                    })
                    .is_err()
                {
                    break;
                }
            }
        });
    } else {
        std::thread::spawn(move || {
            let mut pcap_reader = pcap::PcapReader::new(pcap_file).expect("PCAP Reader");

            while let Some(Ok(packet)) = pcap_reader.next_packet() {
                let ethernet = EthernetPacket::new(&packet.data).expect("ethernet packet");
                if ethernet.get_ethertype().0 != 0x88a4 {
                    continue;
                }
                let timestamp = packet.timestamp;
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
                        timestamp: timestamp,
                        from_main: false,
                        data: ethercat_packet,
                    })
                    .is_err()
                {
                    break;
                }
            }
        });
    }
    (tx_recycle, rx_data)
}

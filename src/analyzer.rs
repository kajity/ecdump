use log::{debug, error, info, trace};

use crate::ec_packet::ECFrame;
use ecdump::ec_packet::ECPacketError;
use ecdump::subdevice::SubDevice;

#[derive(Debug)]
pub enum ECError {
    InvalidDatagram(ECPacketError),
    UnsupportedCommand,
}

pub struct DeviceManager {
    uninitialized: bool,
    num_frames: u64,
    devices: Vec<SubDevice>,
}

impl DeviceManager {
    pub fn new() -> Self {
        DeviceManager {
            uninitialized: true,
            num_frames: 0,
            devices: Vec::new(),
        }
    }

    pub fn analyze_packet(&mut self, packet: &ECFrame, from_main: bool) -> Result<(), ECError> {
        if packet.protocol_type() != 0x01 {
            return Err(ECError::InvalidDatagram(ECPacketError::InvalidHeader));
        }
        let datagrams = packet
            .parse_datagram()
            .map_err(|e| ECError::InvalidDatagram(e))?;

        if self.uninitialized && !from_main {
            let num_subdevices = datagrams.iter().map(|d| d.wkc()).sum::<u16>();
            self.devices = (0..num_subdevices).map(|_| SubDevice::new()).collect();
            self.uninitialized = false;
            debug!(
                "Initialized DeviceManager with {} subdevices",
                num_subdevices
            );
        }

        for d in datagrams.iter() {
            trace!(
                "Parsed EtherCAT Datagram -> command: {}, length: {}",
                d.command().as_str(),
                d.length()
            );
        }
        self.num_frames += 1;
        for device in &mut self.devices {
            for datagram in datagrams.iter() {
                device.process(datagram, from_main);
            }
        }
        Ok(())
    }
}

impl Drop for DeviceManager {
    fn drop(&mut self) {
        debug!("Total analyzed EtherCAT frames: {}", self.num_frames);
    }
}

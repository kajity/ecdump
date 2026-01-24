use std::result;
use std::time::Duration;

use log::{debug, error, info, trace};
use netdev::net::device;

use crate::ec_packet::ECFrame;
use ecdump::ec_packet::{ECCommand, ECCommands, ECDatagram, ECPacketError};
use ecdump::subdevice::SubDevice;

#[derive(Debug)]
pub enum ECError {
    InvalidDatagram(ECPacketError),
    InvalidAutoIncrementAddress(u16),
    UnsupportedCommand,
}

pub struct DeviceManager {
    uninitialized: bool,
    last_wkc: u16,
    num_frames: u64,
    devices: Vec<SubDevice>,
}

impl DeviceManager {
    pub fn new() -> Self {
        DeviceManager {
            uninitialized: true,
            last_wkc: 0,
            num_frames: 0,
            devices: Vec::new(),
        }
    }

    pub fn analyze_packet(
        &mut self,
        packet: &ECFrame,
        timestamp: Duration,
        from_main: bool,
    ) -> Result<(), ECError> {
        if packet.protocol_type() != 0x01 {
            return Err(ECError::InvalidDatagram(ECPacketError::InvalidHeader));
        }
        let datagrams = packet
            .parse_datagram()
            .map_err(|e| ECError::InvalidDatagram(e))?;

        for d in datagrams.iter() {
            trace!(
                "Parsed EtherCAT Datagram -> command: {}, length: {}",
                d.command().as_str(),
                d.length()
            );
        }

        self.num_frames += 1;

        for datagram in datagrams.iter() {
            match datagram.command() {
                ECCommands::BRD => {
                    BrdCommand {
                        timestamp,
                        from_main,
                    }
                    .process_common(self, datagram)?;
                }
                ECCommands::BWR => {
                    BwrCommand {
                        timestamp,
                        from_main,
                    }
                    .process_common(self, datagram)?;
                }
                ECCommands::APWR => {
                    ApwrCommand {
                        timestamp,
                        from_main,
                    }
                    .process_common(self, datagram)?;
                }
                _ => {}
            }
        }

        Ok(())
    }
}

impl Drop for DeviceManager {
    fn drop(&mut self) {
        debug!("Total analyzed EtherCAT frames: {}", self.num_frames);
        for (i, device) in self.devices.iter().enumerate() {
            info!("SubDevice {}: {:?}", i, device.configured_address());
        }
    }
}

trait Command {
    fn process_common(
        &self,
        device_manager: &mut DeviceManager,
        datagram: &ECDatagram,
    ) -> Result<(), ECError> {
        if self.uninitialized(device_manager) {
            return Ok(());
        }

        self.process(device_manager, datagram).map_err(|e| {
            error!("{:?} : frame {}", e, device_manager.num_frames);
            e
        })?;
        if !self.check_wkc(device_manager, datagram) {
            error!(
                "WKC check failed for command {} {} {}",
                device_manager.num_frames,
                datagram.command().as_str(),
                datagram.wkc()
            );
        }

        Ok(())
    }

    fn process(
        &self,
        device_manager: &mut DeviceManager,
        datagram: &ECDatagram,
    ) -> Result<(), ECError>;
    fn check_wkc(&self, device_manager: &mut DeviceManager, datagram: &ECDatagram) -> bool;
    fn uninitialized(&self, device_manager: &DeviceManager) -> bool;
}

struct BrdCommand {
    timestamp: Duration,
    from_main: bool,
}
impl Command for BrdCommand {
    fn process(
        &self,
        device_manager: &mut DeviceManager,
        datagram: &ECDatagram,
    ) -> Result<(), ECError> {
        if device_manager.uninitialized && !self.from_main {
            let num_subdevices = datagram.wkc();
            device_manager.devices = (0..num_subdevices).map(|i| SubDevice::new(i)).collect();
            device_manager.uninitialized = false;
            debug!(
                "Initialized DeviceManager with {} subdevices",
                num_subdevices
            );
        }
        Ok(())
    }

    fn check_wkc(&self, device_manager: &mut DeviceManager, datagram: &ECDatagram) -> bool {
        if self.from_main {
            device_manager.last_wkc = datagram.wkc();
            true
        } else {
            let expected_wkc = device_manager.last_wkc + device_manager.devices.len() as u16;
            datagram.wkc() == expected_wkc
        }
    }

    fn uninitialized(&self, device_manager: &DeviceManager) -> bool {
        device_manager.uninitialized && self.from_main
    }
}

struct BwrCommand {
    timestamp: Duration,
    from_main: bool,
}
impl Command for BwrCommand {
    fn process(
        &self,
        device_manager: &mut DeviceManager,
        datagram: &ECDatagram,
    ) -> Result<(), ECError> {
        let reg_addr = datagram.address().1;
        let data_len = datagram.length();
        for device in device_manager.devices.iter_mut() {
            let data = &datagram.payload()[0..datagram.length() as usize];
            device.write_reg(reg_addr, data);
        }
        Ok(())
    }

    fn check_wkc(&self, device_manager: &mut DeviceManager, datagram: &ECDatagram) -> bool {
        if self.from_main {
            device_manager.last_wkc = datagram.wkc();
            true
        } else {
            let expected_wkc = device_manager.last_wkc + device_manager.devices.len() as u16;
            datagram.wkc() == expected_wkc
        }
    }

    fn uninitialized(&self, device_manager: &DeviceManager) -> bool {
        device_manager.uninitialized
    }
}

struct ApwrCommand {
    timestamp: Duration,
    from_main: bool,
}
impl Command for ApwrCommand {
    fn process(
        &self,
        device_manager: &mut DeviceManager,
        datagram: &ECDatagram,
    ) -> Result<(), ECError> {
        let auto_increment_addr = datagram.address().0;
        let subdevice_index = 0_u16.wrapping_sub(auto_increment_addr) as usize;
        if (self.from_main && subdevice_index >= device_manager.devices.len())
            || (!self.from_main && auto_increment_addr > device_manager.devices.len() as u16)
        {
            return Err(ECError::InvalidAutoIncrementAddress(auto_increment_addr));
        }

        if self.from_main {
            let reg_addr = datagram.address().1;
            let device = &mut device_manager.devices[subdevice_index];
            let data = &datagram.payload()[0..datagram.length() as usize];
            device.write_reg(reg_addr, data);
        }

        Ok(())
    }

    fn check_wkc(&self, device_manager: &mut DeviceManager, datagram: &ECDatagram) -> bool {
        if self.from_main {
            device_manager.last_wkc = datagram.wkc();
            true
        } else {
            let expected_wkc = device_manager.last_wkc + 1;
            datagram.wkc() == expected_wkc
        }
    }

    fn uninitialized(&self, device_manager: &DeviceManager) -> bool {
        device_manager.uninitialized
    }
}

struct FpwrCommand {
    timestamp: Duration,
    from_main: bool,
}
impl Command for FpwrCommand {
    fn process(
        &self,
        device_manager: &mut DeviceManager,
        datagram: &ECDatagram,
    ) -> Result<(), ECError> {
        // Implementation for FPWR command processing
        Ok(())
    }

    fn check_wkc(&self, device_manager: &mut DeviceManager, datagram: &ECDatagram) -> bool {
        if self.from_main {
            device_manager.last_wkc = datagram.wkc();
            true
        } else {
            let expected_wkc = device_manager.last_wkc + 1;
            datagram.wkc() == expected_wkc
        }
    }

    fn uninitialized(&self, device_manager: &DeviceManager) -> bool {
        device_manager.uninitialized
    }
}

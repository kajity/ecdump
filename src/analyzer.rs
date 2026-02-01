use std::collections::HashMap;
use std::time::Duration;

use log::{debug, error, info, trace, warn};

use crate::ec_packet::ECFrame;
use ecdump::ec_packet::{ECCommand, ECCommands, ECDatagram, ECPacketError};
use ecdump::subdevice::{self, ESMError, SubDevice};

#[derive(Debug)]
pub enum ECError {
    InvalidDatagram(ECPacketError),
    InvalidAutoIncrementAddress(u16),
    InvalidConfiguredAddress(u16),
    InvalidWkc {
        packet_number: u64,
        command: ECCommand,
        from_main: bool,
        timestamp: Duration,
        expected: u16,
        actual: u16,
    },
    UnsupportedCommand,
}

pub struct DeviceManager {
    uninitialized: bool,
    num_frames: u64,
    expected_wkc: u16,
    devices: Vec<SubDevice>,
    config_address_map: HashMap<u16, usize>,
}

impl DeviceManager {
    pub fn new() -> Self {
        DeviceManager {
            uninitialized: true,
            num_frames: 0,
            expected_wkc: 0,
            devices: Vec::new(),
            config_address_map: HashMap::new(),
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
        let datagrams = packet.parse_datagram().map_err(ECError::InvalidDatagram)?;

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
                ECCommands::APRD => {
                    AprdCommand {
                        timestamp,
                        from_main,
                    }
                    .process_common(self, datagram)?;
                }
                ECCommands::FPWR => {
                    FpwrCommand {
                        timestamp,
                        from_main,
                    }
                    .process_common(self, datagram)?;
                }
                ECCommands::FPRD => {
                    FprdCommand {
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
        for (i, device) in self.devices.iter_mut().enumerate() {
            // info!("SubDevice {}: {:?}", i, device.configured_address());
        }
    }
}

trait Command {
    fn process_common(
        &self,
        device_manager: &mut DeviceManager,
        datagram: &ECDatagram,
    ) -> Result<(), ECError> {
        if self.uninitialized(device_manager, datagram) {
            return Ok(());
        }

        if !self.check_wkc(device_manager, datagram) {
            info!(
                "WKC check failed: #{} {} expected {}, got {}",
                device_manager.num_frames,
                datagram.command().as_str(),
                device_manager.expected_wkc,
                datagram.wkc()
            );
            return Err(ECError::InvalidWkc {
                packet_number: device_manager.num_frames,
                command: datagram.command(),
                from_main: self.from_main(),
                timestamp: self.timestamp(),
                expected: device_manager.expected_wkc,
                actual: datagram.wkc(),
            });
        }

        self.process(device_manager, datagram).map_err(|e| {
            error!("{:?} : frame {}", e, device_manager.num_frames);
            e
        })?;

        Ok(())
    }

    fn process(
        &self,
        device_manager: &mut DeviceManager,
        datagram: &ECDatagram,
    ) -> Result<(), ECError>;

    fn uninitialized(&self, device_manager: &mut DeviceManager, datagram: &ECDatagram) -> bool {
        device_manager.uninitialized
    }

    fn check_wkc(&self, device_manager: &mut DeviceManager, datagram: &ECDatagram) -> bool;

    fn timestamp(&self) -> Duration;

    fn from_main(&self) -> bool;
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
        if !self.from_main {
            for device in device_manager.devices.iter_mut() {
                let reg_addr = datagram.address().1;
                let data = &datagram.payload()[0..datagram.length() as usize];
                device.write_reg_brd(reg_addr, data);

                device
                    .state_machine_step::<subdevice::BrdCommandStepper>(device_manager.num_frames);
            }
        }

        Ok(())
    }

    fn check_wkc(&self, device_manager: &mut DeviceManager, datagram: &ECDatagram) -> bool {
        if self.from_main {
            true
        } else {
            device_manager.expected_wkc = device_manager.devices.len() as u16;
            datagram.wkc() == device_manager.expected_wkc
        }
    }

    fn uninitialized(&self, device_manager: &mut DeviceManager, datagram: &ECDatagram) -> bool {
        if device_manager.uninitialized && !self.from_main {
            let num_subdevices = datagram.wkc();
            device_manager.devices = (0..num_subdevices).map(|_| SubDevice::new()).collect();
            device_manager.uninitialized = false;
            debug!(
                "Initialized DeviceManager with {} subdevices",
                num_subdevices
            );
            false
        } else {
            device_manager.uninitialized
        }
    }

    fn timestamp(&self) -> Duration {
        self.timestamp
    }

    fn from_main(&self) -> bool {
        self.from_main
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
        if !self.from_main {
            return Ok(());
        }

        let reg_addr = datagram.address().1;
        for device in device_manager.devices.iter_mut() {
            let data = &datagram.payload()[0..datagram.length() as usize];
            device.write_reg_wr(reg_addr, data);
        }
        Ok(())
    }

    fn check_wkc(&self, device_manager: &mut DeviceManager, datagram: &ECDatagram) -> bool {
        if self.from_main {
            true
        } else {
            device_manager.expected_wkc = device_manager.devices.len() as u16;
            datagram.wkc() == device_manager.expected_wkc
        }
    }

    fn timestamp(&self) -> Duration {
        self.timestamp
    }

    fn from_main(&self) -> bool {
        self.from_main
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
        let subdevice_index = if self.from_main {
            0_u16.wrapping_sub(auto_increment_addr) as usize
        } else {
            device_manager
                .devices
                .len()
                .wrapping_sub(auto_increment_addr as usize)
        };
        if subdevice_index >= device_manager.devices.len() {
            return Err(ECError::InvalidAutoIncrementAddress(auto_increment_addr));
        }

        if !self.from_main {
            let reg_addr = datagram.address().1;
            let device = &mut device_manager.devices[subdevice_index];
            let data = &datagram.payload()[0..datagram.length() as usize];
            device.write_reg_wr(reg_addr, data);
        }

        Ok(())
    }

    fn check_wkc(&self, device_manager: &mut DeviceManager, datagram: &ECDatagram) -> bool {
        if self.from_main {
            true
        } else {
            device_manager.expected_wkc = 1;
            datagram.wkc() == device_manager.expected_wkc
        }
    }

    fn timestamp(&self) -> Duration {
        self.timestamp
    }

    fn from_main(&self) -> bool {
        self.from_main
    }
}

struct AprdCommand {
    timestamp: Duration,
    from_main: bool,
}
impl Command for AprdCommand {
    fn process(
        &self,
        device_manager: &mut DeviceManager,
        datagram: &ECDatagram,
    ) -> Result<(), ECError> {
        let auto_increment_addr = datagram.address().0;
        let subdevice_index = if self.from_main {
            0_u16.wrapping_sub(auto_increment_addr) as usize
        } else {
            device_manager
                .devices
                .len()
                .wrapping_sub(auto_increment_addr as usize)
        };
        if subdevice_index >= device_manager.devices.len() {
            return Err(ECError::InvalidAutoIncrementAddress(auto_increment_addr));
        }

        if !self.from_main {
            let reg_addr = datagram.address().1;
            let device = &mut device_manager.devices[subdevice_index];
            let data = &datagram.payload()[0..datagram.length() as usize];
            device.write_reg_rd(reg_addr, data);

            device.state_machine_step::<subdevice::AprdCommandStepper>(device_manager.num_frames);

            if let Some(configured_address) = device.configured_address() {
                device_manager
                    .config_address_map
                    .insert(configured_address, subdevice_index);
            }
        }

        // for (i, (returned_data, reg_data)) in datagram.payload()[0..data_len]
        //     .iter()
        //     .zip(device_manager.devices[subdevice_index].read_reg(reg_addr, data_len as u16))
        //     .enumerate()
        // {
        //     if let Some(reg_byte) = reg_data {
        //         if *returned_data != reg_byte {
        //             debug!(
        //                 "#{} APRD data mismatch at SubDevice {} reg {:#06x}: expected {:#04x}, got {:#04x}",
        //                 device_manager.num_frames,
        //                 subdevice_index, reg_addr + i as u16, reg_byte, *returned_data
        //             );
        //         }
        //     } else {
        //         debug!(
        //             "#{} APRD data missing at SubDevice {} reg {:#06x}",
        //             device_manager.num_frames,
        //             subdevice_index, reg_addr + i as u16
        //         );
        //     }
        // }

        Ok(())
    }

    fn check_wkc(&self, device_manager: &mut DeviceManager, datagram: &ECDatagram) -> bool {
        if self.from_main {
            true
        } else {
            device_manager.expected_wkc = 1;
            datagram.wkc() == device_manager.expected_wkc
        }
    }

    fn timestamp(&self) -> Duration {
        self.timestamp
    }

    fn from_main(&self) -> bool {
        self.from_main
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
        if !self.from_main {
            return Ok(());
        }

        let configured_address = datagram.address().0;
        let device = &mut device_manager.devices[*device_manager
            .config_address_map
            .get(&configured_address)
            .ok_or(ECError::InvalidConfiguredAddress(configured_address))?];

        let reg_addr = datagram.address().1;
        let data = &datagram.payload()[0..datagram.length() as usize];
        device.write_reg_wr(reg_addr, data);

        Ok(())
    }

    fn check_wkc(&self, device_manager: &mut DeviceManager, datagram: &ECDatagram) -> bool {
        if self.from_main {
            true
        } else {
            device_manager.expected_wkc = 1;
            datagram.wkc() == device_manager.expected_wkc
        }
    }

    fn timestamp(&self) -> Duration {
        self.timestamp
    }

    fn from_main(&self) -> bool {
        self.from_main
    }
}

struct FprdCommand {
    timestamp: Duration,
    from_main: bool,
}
impl Command for FprdCommand {
    fn process(
        &self,
        device_manager: &mut DeviceManager,
        datagram: &ECDatagram,
    ) -> Result<(), ECError> {
        let configured_address = datagram.address().0;
        let subdevice = &mut device_manager.devices[*device_manager
            .config_address_map
            .get(&configured_address)
            .ok_or(ECError::InvalidConfiguredAddress(configured_address))?];

        if !self.from_main {
            let reg_addr = datagram.address().1;
            let data = &datagram.payload()[0..datagram.length() as usize];
            subdevice.write_reg_rd(reg_addr, data);

            subdevice
                .state_machine_step::<subdevice::FprdCommandStepper>(device_manager.num_frames);
        }

        Ok(())
    }

    fn check_wkc(&self, device_manager: &mut DeviceManager, datagram: &ECDatagram) -> bool {
        if self.from_main {
            true
        } else {
            device_manager.expected_wkc = 1;
            datagram.wkc() == device_manager.expected_wkc
        }
    }

    fn timestamp(&self) -> Duration {
        self.timestamp
    }

    fn from_main(&self) -> bool {
        self.from_main
    }
}

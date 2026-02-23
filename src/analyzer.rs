use std::collections::HashMap;
use std::collections::VecDeque;
use std::time::Duration;

use log::{debug, error, info, trace, warn};

use crate::ec_packet::ECFrame;
use ecdump::ec_packet::{ECCommand, ECCommands, ECDatagram, ECPacketError};
use ecdump::subdevice::{self, ESMError, SubDevice, SubdeviceIdentifier};

#[derive(Debug, Clone)]
pub struct WkcErrorDetail {
    pub packet_number: u64,
    pub command: ECCommand,
    pub from_main: bool,
    pub timestamp: Duration,
    pub expected: u16,
    pub actual: u16,
    pub subdevice_id: Option<SubdeviceIdentifier>,
}

#[derive(Debug, Clone)]
pub struct ESMErrorDetail {
    pub packet_number: u64,
    pub timestamp: Duration,
    pub command: ECCommand,
    pub subdevice_id: SubdeviceIdentifier,
    pub error: ESMError,
}

#[derive(Debug, Clone)]
pub enum ECDeviceError {
    InvalidAutoIncrementAddress {
        packet_number: u64,
        timestamp: Duration,
        command: ECCommand,
        address: u16,
    },
    InvalidConfiguredAddress {
        packet_number: u64,
        timestamp: Duration,
        command: ECCommand,
        address: u16,
    },
    InvalidWkc(WkcErrorDetail),
    ESMError(ESMErrorDetail),
}

#[derive(Debug)]
pub enum ECError {
    InvalidDatagram(ECPacketError),
    DeviceError(Vec<ECDeviceError>),
}

#[derive(Debug, Clone)]
pub struct ErrorAggregation {
    pub error: ECDeviceError,
    pub count: usize,
    pub first_packet_number: u64,
    pub last_packet_number: u64,
    pub related_wkc_error: Option<Box<ECDeviceError>>,
    pub first_timestamp: Duration,
    pub last_timestamp: Duration,
}

#[derive(Debug, Clone)]
pub struct ErrorCorrelation {
    pub wkc_error: ECDeviceError,
    pub esm_error: Option<ESMError>,
    pub frame_gap: u64,
}

pub struct DeviceManager {
    uninitialized: bool,
    num_frames: u64,
    expected_wkc: u16,
    devices: Vec<SubDevice>,
    config_address_map: HashMap<u16, usize>,
    error_aggregations: Vec<ErrorAggregation>,
    wkc_error_history: VecDeque<(u64, ECDeviceError)>,
    correlations: Vec<ErrorCorrelation>,
    consecutive_same_errors: usize,
    last_error_type: Option<String>,
}

impl DeviceManager {
    pub fn new() -> Self {
        DeviceManager {
            uninitialized: true,
            num_frames: 0,
            expected_wkc: 0,
            devices: Vec::new(),
            config_address_map: HashMap::new(),
            error_aggregations: Vec::new(),
            wkc_error_history: VecDeque::new(),
            correlations: Vec::new(),
            consecutive_same_errors: 0,
            last_error_type: None,
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
        self.num_frames += 1;

        for d in datagrams.iter() {
            trace!(
                "Parsed EtherCAT Datagram #{} -> command: {}, length: {}",
                self.num_frames,
                d.command().as_str(),
                d.length()
            );
        }

        let mut errors = Vec::<ECDeviceError>::new();
        for datagram in datagrams.iter() {
            let result = match datagram.command() {
                ECCommands::BRD => BrdCommand {
                    timestamp,
                    from_main,
                }
                .process_common(self, datagram),
                ECCommands::BWR => BwrCommand {
                    timestamp,
                    from_main,
                }
                .process_common(self, datagram),
                ECCommands::APWR => ApwrCommand {
                    timestamp,
                    from_main,
                }
                .process_common(self, datagram),
                ECCommands::APRD => AprdCommand {
                    timestamp,
                    from_main,
                }
                .process_common(self, datagram),
                ECCommands::FPWR => FpwrCommand {
                    timestamp,
                    from_main,
                }
                .process_common(self, datagram),
                ECCommands::FPRD => FprdCommand {
                    timestamp,
                    from_main,
                }
                .process_common(self, datagram),
                _ => Ok(()),
            };

            match result {
                Err(ECDeviceError::InvalidAutoIncrementAddress {
                    packet_number,
                    address,
                    ..
                }) => {
                    warn!(
                        "Invalid auto-increment address {:#06x} in frame #{}",
                        address, packet_number
                    );
                    errors.push(ECDeviceError::InvalidAutoIncrementAddress {
                        packet_number,
                        timestamp,
                        command: datagram.command(),
                        address,
                    });
                }
                Err(ECDeviceError::InvalidConfiguredAddress {
                    packet_number,
                    address,
                    ..
                }) => {
                    warn!(
                        "Invalid configured address {:#06x} in frame #{}",
                        address, packet_number
                    );
                    errors.push(ECDeviceError::InvalidConfiguredAddress {
                        packet_number,
                        timestamp,
                        command: datagram.command(),
                        address,
                    });
                }
                Err(ECDeviceError::InvalidWkc(wkc_err)) => {
                    let dev_str = wkc_err
                        .subdevice_id
                        .as_ref()
                        .map(|s| format!(" [{}]", s))
                        .unwrap_or_default();
                    if wkc_err.from_main {
                        debug!(
                            "#{} WKC error (main->device): {}{}, adp {:04x}, ado {:#06x}, expected {}, got {}",
                            wkc_err.packet_number,
                            wkc_err.command.as_str(),
                            dev_str,
                            datagram.address().0,
                            datagram.address().1,
                            wkc_err.expected,
                            wkc_err.actual,
                        );
                    } else {
                        warn!(
                            "#{} WKC error: {}{}, adp {:04x}, ado {:#06x}, expected {}, got {}",
                            wkc_err.packet_number,
                            wkc_err.command.as_str(),
                            dev_str,
                            datagram.address().0,
                            datagram.address().1,
                            wkc_err.expected,
                            wkc_err.actual,
                        );
                    }

                    let err = ECDeviceError::InvalidWkc(WkcErrorDetail {
                        packet_number: wkc_err.packet_number,
                        command: wkc_err.command,
                        from_main: wkc_err.from_main,
                        timestamp: wkc_err.timestamp,
                        expected: wkc_err.expected,
                        actual: wkc_err.actual,
                        subdevice_id: wkc_err.subdevice_id,
                    });
                    self.aggregate_error(&err, timestamp);
                    // ESM ErrorがWKC Errorに関連している可能性をチェック
                    if let ECDeviceError::ESMError(_) = &err {
                        // self.correlate_esm_with_wkc(&err);
                    }

                    if let ECDeviceError::InvalidWkc(_) = &err {
                        if self.wkc_error_history.len() >= 50 {
                            self.wkc_error_history.pop_front();
                        }
                        self.wkc_error_history
                            .push_back((self.num_frames, err.clone()));
                    }
                    errors.push(err);
                }
                Err(ECDeviceError::ESMError(esm_error)) => {
                    error!(
                        "#{} ESM Error [{}]: {:?}",
                        esm_error.packet_number, esm_error.subdevice_id, esm_error.error
                    );
                    errors.push(ECDeviceError::ESMError(esm_error));
                }
                _ => {}
            }
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(ECError::DeviceError(errors))
        }
    }

    // TODO: ESMエラーとWKCエラーの関連性を分析するためのロジック
    fn correlate_esm_with_wkc(&mut self, esm_error: &ESMError) {
        for (frame_num, wkc_err) in self.wkc_error_history.iter().rev() {
            if self.num_frames - frame_num <= 10 {
                let correlation = ErrorCorrelation {
                    wkc_error: wkc_err.clone(),
                    esm_error: Some(esm_error.clone()),
                    frame_gap: self.num_frames - frame_num,
                };
                self.correlations.push(correlation);
                debug!(
                    "Correlated ESM Error with WKC Error from frame #{} (gap: {} frames)",
                    frame_num,
                    self.num_frames - frame_num
                );
                break;
            }
        }
    }

    fn aggregate_error(&mut self, error: &ECDeviceError, timestamp: Duration) {
        if let Some(last_agg) = self.error_aggregations.last_mut() {
            if Self::errors_are_same(&last_agg.error, error) {
                last_agg.count += 1;
                last_agg.last_packet_number = self.num_frames;
                last_agg.last_timestamp = timestamp;
                self.consecutive_same_errors += 1;

                if self.consecutive_same_errors > 5 {
                    debug!(
                        "Burst of {} consecutive similar errors detected",
                        self.consecutive_same_errors
                    );
                }
                return;
            }
        }

        let error_type = match error {
            ECDeviceError::InvalidWkc(WkcErrorDetail { command, .. }) => {
                format!("WKC_{}", command.as_str())
            }
            ECDeviceError::ESMError(_) => "ESM".to_string(),
            ECDeviceError::InvalidAutoIncrementAddress { .. } => "AUTOINC_ADDR".to_string(),
            ECDeviceError::InvalidConfiguredAddress { .. } => "CONFIG_ADDR".to_string(),
        };

        if self.last_error_type.as_ref() != Some(&error_type) {
            self.consecutive_same_errors = 1;
            self.last_error_type = Some(error_type);
        }

        let mut aggregation = ErrorAggregation {
            error: error.clone(),
            count: 1,
            first_packet_number: self.num_frames,
            last_packet_number: self.num_frames,
            related_wkc_error: None,
            first_timestamp: timestamp,
            last_timestamp: timestamp,
        };

        if let ECDeviceError::ESMError(_) = error {
            if let Some((_, wkc_err)) = self.wkc_error_history.back() {
                if self.num_frames - self.wkc_error_history.back().unwrap().0 <= 10 {
                    aggregation.related_wkc_error = Some(Box::new(wkc_err.clone()));
                }
            }
        }

        self.error_aggregations.push(aggregation);
    }

    fn errors_are_same(err1: &ECDeviceError, err2: &ECDeviceError) -> bool {
        match (err1, err2) {
            (
                ECDeviceError::InvalidAutoIncrementAddress { address: a1, .. },
                ECDeviceError::InvalidAutoIncrementAddress { address: a2, .. },
            ) => a1 == a2,
            (
                ECDeviceError::InvalidConfiguredAddress { address: a1, .. },
                ECDeviceError::InvalidConfiguredAddress { address: a2, .. },
            ) => a1 == a2,
            (
                ECDeviceError::InvalidWkc(WkcErrorDetail {
                    command: cmd1,
                    expected: e1,
                    actual: a1,
                    subdevice_id: s1,
                    ..
                }),
                ECDeviceError::InvalidWkc(WkcErrorDetail {
                    command: cmd2,
                    expected: e2,
                    actual: a2,
                    subdevice_id: s2,
                    ..
                }),
            ) => cmd1 == cmd2 && e1 == e2 && a1 == a2 && s1 == s2,
            (
                ECDeviceError::ESMError(ESMErrorDetail {
                    error: e1,
                    subdevice_id: s1,
                    ..
                }),
                ECDeviceError::ESMError(ESMErrorDetail {
                    error: e2,
                    subdevice_id: s2,
                    ..
                }),
            ) => std::mem::discriminant(e1) == std::mem::discriminant(e2) && s1 == s2,
            _ => false,
        }
    }

    pub fn get_frame_count(&self) -> u64 {
        self.num_frames
    }

    pub fn get_error_aggregations(&self) -> &[ErrorAggregation] {
        &self.error_aggregations
    }

    pub fn get_error_correlations(&self) -> &[ErrorCorrelation] {
        &self.correlations
    }

    pub fn has_burst_errors(&self) -> bool {
        self.consecutive_same_errors > 5
    }

    pub fn get_consecutive_error_count(&self) -> usize {
        self.consecutive_same_errors
    }
}

impl Drop for DeviceManager {
    fn drop(&mut self) {
        debug!("Total analyzed EtherCAT frames: {}", self.num_frames);
        for (i, device) in self.devices.iter_mut().enumerate() {
            debug!("SubDevice {}: {}", i, device.identifier());
            // debug!("subdevice {}: {:?}", i, device.configured_address())
        }
    }
}

trait Command {
    fn process_common(
        &self,
        manager: &mut DeviceManager,
        datagram: &ECDatagram,
    ) -> Result<(), ECDeviceError> {
        if self.uninitialized(manager, datagram) {
            return Ok(());
        }

        if !self.check_wkc(manager, datagram) {
            self.process_fallback(manager, datagram);
            return Err(ECDeviceError::InvalidWkc(WkcErrorDetail {
                packet_number: manager.num_frames,
                command: datagram.command(),
                from_main: self.from_main(),
                timestamp: self.timestamp(),
                subdevice_id: self.get_subdevice_id(manager, datagram),
                expected: manager.expected_wkc,
                actual: datagram.wkc(),
            }));
        }

        self.process(manager, datagram)
    }

    fn process(
        &self,
        manager: &mut DeviceManager,
        datagram: &ECDatagram,
    ) -> Result<(), ECDeviceError>;

    fn process_fallback(&self, manager: &mut DeviceManager, datagram: &ECDatagram) {}

    fn uninitialized(&self, manager: &mut DeviceManager, datagram: &ECDatagram) -> bool {
        manager.uninitialized
    }

    fn check_wkc(&self, maanger: &mut DeviceManager, datagram: &ECDatagram) -> bool;

    fn timestamp(&self) -> Duration;

    fn from_main(&self) -> bool;

    fn get_subdevice_id(
        &self,
        manager: &DeviceManager,
        datagram: &ECDatagram,
    ) -> Option<SubdeviceIdentifier>;
}

struct BrdCommand {
    timestamp: Duration,
    from_main: bool,
}

impl Command for BrdCommand {
    fn process(
        &self,
        manager: &mut DeviceManager,
        datagram: &ECDatagram,
    ) -> Result<(), ECDeviceError> {
        if !self.from_main {
            for device in manager.devices.iter_mut() {
                let reg_addr = datagram.address().1;
                let data = &datagram.payload()[0..datagram.length() as usize];
                device.write_reg_brd(reg_addr, data);

                device
                    .state_machine_step::<subdevice::BrdCommandStepper>(manager.num_frames)
                    .map_err(|e| {
                        ECDeviceError::ESMError(ESMErrorDetail {
                            packet_number: manager.num_frames,
                            timestamp: self.timestamp,
                            command: datagram.command(),
                            subdevice_id: device.identifier(),
                            error: e,
                        })
                    })?;
            }
        }

        Ok(())
    }

    fn check_wkc(&self, manager: &mut DeviceManager, datagram: &ECDatagram) -> bool {
        if self.from_main {
            true
        } else {
            manager.expected_wkc = manager.devices.len() as u16;
            datagram.wkc() == manager.expected_wkc
        }
    }

    fn uninitialized(&self, manager: &mut DeviceManager, datagram: &ECDatagram) -> bool {
        if manager.uninitialized && !self.from_main {
            let num_subdevices = datagram.wkc();
            manager.devices = (0..num_subdevices).map(|_| SubDevice::new()).collect();
            manager.uninitialized = false;
            debug!(
                "Initialized DeviceManager with {} subdevices",
                num_subdevices
            );
            false
        } else {
            manager.uninitialized
        }
    }

    fn timestamp(&self) -> Duration {
        self.timestamp
    }

    fn from_main(&self) -> bool {
        self.from_main
    }

    fn get_subdevice_id(
        &self,
        _manager: &DeviceManager,
        _datagram: &ECDatagram,
    ) -> Option<SubdeviceIdentifier> {
        None
    }
}

struct BwrCommand {
    timestamp: Duration,
    from_main: bool,
}

impl Command for BwrCommand {
    fn process(
        &self,
        manager: &mut DeviceManager,
        datagram: &ECDatagram,
    ) -> Result<(), ECDeviceError> {
        let reg_addr = datagram.address().1;
        let data = datagram.payload();
        for device in manager.devices.iter_mut() {
            device.write_reg_wr(reg_addr, data);
        }
        Ok(())
    }

    fn process_fallback(&self, manager: &mut DeviceManager, datagram: &ECDatagram) {
        self.process(manager, datagram).ok();
    }

    fn check_wkc(&self, manager: &mut DeviceManager, datagram: &ECDatagram) -> bool {
        if self.from_main {
            true
        } else {
            manager.expected_wkc = manager.devices.len() as u16;
            datagram.wkc() == manager.expected_wkc
        }
    }

    fn timestamp(&self) -> Duration {
        self.timestamp
    }

    fn from_main(&self) -> bool {
        self.from_main
    }

    fn get_subdevice_id(
        &self,
        _manager: &DeviceManager,
        _datagram: &ECDatagram,
    ) -> Option<SubdeviceIdentifier> {
        None
    }
}

struct ApwrCommand {
    timestamp: Duration,
    from_main: bool,
}

impl Command for ApwrCommand {
    fn process(
        &self,
        manager: &mut DeviceManager,
        datagram: &ECDatagram,
    ) -> Result<(), ECDeviceError> {
        let auto_increment_addr = datagram.address().0;
        let subdevice_index = self
            .get_idx_from_auto_increment_address(manager, auto_increment_addr)
            .ok_or(ECDeviceError::InvalidAutoIncrementAddress {
                packet_number: manager.num_frames,
                timestamp: self.timestamp,
                command: datagram.command(),
                address: auto_increment_addr,
            })?;

        if !self.from_main {
            let reg_addr = datagram.address().1;
            let device = &mut manager.devices[subdevice_index];
            let data = &datagram.payload()[0..datagram.length() as usize];
            device.write_reg_wr(reg_addr, data);
        }

        Ok(())
    }

    fn process_fallback(&self, manager: &mut DeviceManager, datagram: &ECDatagram) {
        let auto_increment_addr = datagram.address().0;
        if !self.from_main
            && let Some(subdevice_index) =
                self.get_idx_from_auto_increment_address(manager, auto_increment_addr)
        {
            let reg_addr = datagram.address().1;
            let device = &mut manager.devices[subdevice_index];
            let data = &datagram.payload()[0..datagram.length() as usize];
            device.write_reg_wr(reg_addr, data);
        }
    }

    fn check_wkc(&self, manager: &mut DeviceManager, datagram: &ECDatagram) -> bool {
        if self.from_main {
            true
        } else {
            manager.expected_wkc = 1;
            datagram.wkc() == manager.expected_wkc
        }
    }

    fn timestamp(&self) -> Duration {
        self.timestamp
    }

    fn from_main(&self) -> bool {
        self.from_main
    }

    fn get_subdevice_id(
        &self,
        manager: &DeviceManager,
        datagram: &ECDatagram,
    ) -> Option<SubdeviceIdentifier> {
        let auto_increment_addr = datagram.address().0;
        self.get_idx_from_auto_increment_address(manager, auto_increment_addr)
            .map(|idx| manager.devices[idx].identifier())
    }
}

impl ApwrCommand {
    fn get_idx_from_auto_increment_address<'a>(
        &self,
        manager: &DeviceManager,
        auto_increment_addr: u16,
    ) -> Option<usize> {
        let subdevice_index = if self.from_main {
            0_u16.wrapping_sub(auto_increment_addr) as usize
        } else {
            manager
                .devices
                .len()
                .wrapping_sub(auto_increment_addr as usize)
        };

        if subdevice_index >= manager.devices.len() {
            None
        } else {
            Some(subdevice_index)
        }
    }
}

struct AprdCommand {
    timestamp: Duration,
    from_main: bool,
}

impl Command for AprdCommand {
    fn process(
        &self,
        manager: &mut DeviceManager,
        datagram: &ECDatagram,
    ) -> Result<(), ECDeviceError> {
        let auto_increment_addr = datagram.address().0;
        let subdevice_index = self
            .get_index_from_auto_increment_address(manager, auto_increment_addr)
            .ok_or(ECDeviceError::InvalidAutoIncrementAddress {
                packet_number: manager.num_frames,
                timestamp: self.timestamp,
                command: datagram.command(),
                address: auto_increment_addr,
            })?;

        let device = &mut manager.devices[subdevice_index];

        if !self.from_main {
            let reg_addr = datagram.address().1;
            let data = &datagram.payload()[0..datagram.length() as usize];
            device.write_reg_rd(reg_addr, data);

            let esm_result = device
                .state_machine_step::<subdevice::AprdCommandStepper>(manager.num_frames)
                .map_err(|e| {
                    ECDeviceError::ESMError(ESMErrorDetail {
                        packet_number: manager.num_frames,
                        timestamp: self.timestamp,
                        command: datagram.command(),
                        subdevice_id: device.identifier(),
                        error: e,
                    })
                });

            if let Some(configured_address) = device.configured_address() {
                manager
                    .config_address_map
                    .insert(configured_address, subdevice_index);
            }
            esm_result?;
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

    fn get_subdevice_id(
        &self,
        manager: &DeviceManager,
        datagram: &ECDatagram,
    ) -> Option<SubdeviceIdentifier> {
        let auto_increment_addr = datagram.address().0;
        self.get_index_from_auto_increment_address(manager, auto_increment_addr)
            .map(|idx| manager.devices[idx].identifier())
    }
}

impl AprdCommand {
    fn get_index_from_auto_increment_address(
        &self,
        manager: &DeviceManager,
        auto_increment_addr: u16,
    ) -> Option<usize> {
        let idx = if self.from_main {
            0_u16.wrapping_sub(auto_increment_addr) as usize
        } else {
            manager
                .devices
                .len()
                .wrapping_sub(auto_increment_addr as usize)
        };

        if idx >= manager.devices.len() {
            None
        } else {
            Some(idx)
        }
    }
}

struct FpwrCommand {
    timestamp: Duration,
    from_main: bool,
}

impl Command for FpwrCommand {
    fn process(
        &self,
        manager: &mut DeviceManager,
        datagram: &ECDatagram,
    ) -> Result<(), ECDeviceError> {
        let (configured_address, ado) = datagram.address();
        let subdevice_index = manager
            .config_address_map
            .get(&configured_address)
            .ok_or_else(|| {
                return ECDeviceError::InvalidConfiguredAddress {
                    packet_number: manager.num_frames,
                    timestamp: self.timestamp,
                    command: datagram.command(),
                    address: configured_address,
                };
            })?;

        if !self.from_main {
            let data = datagram.payload();
            manager.devices[*subdevice_index].write_reg_wr(ado, data);
        }

        Ok(())
    }

    fn process_fallback(&self, manager: &mut DeviceManager, datagram: &ECDatagram) {
        let (configured_address, ado) = datagram.address();
        if !self.from_main
            && let Some(&subdevice_index) = manager.config_address_map.get(&configured_address)
        {
            let data = datagram.payload();
            manager.devices[subdevice_index].write_reg_wr(ado, data);
        }
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

    fn get_subdevice_id(
        &self,
        manager: &DeviceManager,
        datagram: &ECDatagram,
    ) -> Option<SubdeviceIdentifier> {
        let (configured_address, _) = datagram.address();
        manager
            .config_address_map
            .get(&configured_address)
            .map(|&idx| manager.devices[idx].identifier())
    }
}

struct FprdCommand {
    timestamp: Duration,
    from_main: bool,
}

impl Command for FprdCommand {
    fn process(
        &self,
        manager: &mut DeviceManager,
        datagram: &ECDatagram,
    ) -> Result<(), ECDeviceError> {
        let (configured_address, ado) = datagram.address();
        let subdevice_index = manager
            .config_address_map
            .get(&configured_address)
            .ok_or_else(|| {
                return ECDeviceError::InvalidConfiguredAddress {
                    packet_number: manager.num_frames,
                    timestamp: self.timestamp,
                    command: datagram.command(),
                    address: configured_address,
                };
            })?;
        let device = &mut manager.devices[*subdevice_index];

        if !self.from_main {
            let data = datagram.payload();
            device.write_reg_rd(ado, data);

            if let Err(e) =
                device.state_machine_step::<subdevice::FprdCommandStepper>(manager.num_frames)
            {
                return Err(ECDeviceError::ESMError(ESMErrorDetail {
                    packet_number: manager.num_frames,
                    timestamp: self.timestamp,
                    command: datagram.command(),
                    subdevice_id: device.identifier(),
                    error: e,
                }));
            }
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

    fn get_subdevice_id(
        &self,
        manager: &DeviceManager,
        datagram: &ECDatagram,
    ) -> Option<SubdeviceIdentifier> {
        let (configured_address, _) = datagram.address();
        manager
            .config_address_map
            .get(&configured_address)
            .map(|&idx| manager.devices[idx].identifier())
    }
}

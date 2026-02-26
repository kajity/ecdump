use std::collections::HashMap;
use std::collections::VecDeque;
use std::time::Duration;

use log::{debug, error, trace, warn};

use crate::ec_packet::ECFrame;
use ecdump::ec_packet::{ECCommand, ECCommands, ECDatagram, ECPacketError};
use ecdump::subdevice::{self, ECState, ESMError, SubDevice, SubdeviceIdentifier};

#[derive(Debug, Copy, Clone)]
pub struct WkcErrorDetail {
    pub packet_number: u64,
    pub command: ECCommand,
    pub from_main: bool,
    pub timestamp: Duration,
    pub expected: u16,
    pub actual: u16,
    pub subdevice_id: Option<SubdeviceIdentifier>,
}

#[derive(Debug, Copy, Clone)]
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

#[allow(dead_code)]
impl ECDeviceError {
    /// Returns a human-readable category name for this error type.
    pub fn category_name(&self) -> &'static str {
        match self {
            ECDeviceError::InvalidAutoIncrementAddress { .. } => "Auto-Increment Addr",
            ECDeviceError::InvalidConfiguredAddress { .. } => "Configured Addr",
            ECDeviceError::InvalidWkc(_) => "WKC Mismatch",
            ECDeviceError::ESMError(_) => "ESM Error",
        }
    }

    /// Returns the timestamp associated with this error.
    pub fn timestamp(&self) -> Duration {
        match self {
            ECDeviceError::InvalidAutoIncrementAddress { timestamp, .. } => *timestamp,
            ECDeviceError::InvalidConfiguredAddress { timestamp, .. } => *timestamp,
            ECDeviceError::InvalidWkc(d) => d.timestamp,
            ECDeviceError::ESMError(d) => d.timestamp,
        }
    }

    /// Returns the packet/frame number associated with this error.
    pub fn packet_number(&self) -> u64 {
        match self {
            ECDeviceError::InvalidAutoIncrementAddress { packet_number, .. } => *packet_number,
            ECDeviceError::InvalidConfiguredAddress { packet_number, .. } => *packet_number,
            ECDeviceError::InvalidWkc(d) => d.packet_number,
            ECDeviceError::ESMError(d) => d.packet_number,
        }
    }

    /// Returns the subdevice identifier if available.
    pub fn subdevice_id(&self) -> Option<SubdeviceIdentifier> {
        match self {
            ECDeviceError::InvalidAutoIncrementAddress { .. } => None,
            ECDeviceError::InvalidConfiguredAddress { .. } => None,
            ECDeviceError::InvalidWkc(d) => d.subdevice_id,
            ECDeviceError::ESMError(d) => Some(d.subdevice_id),
        }
    }

    /// Returns the command type associated with this error.
    pub fn command(&self) -> ECCommand {
        match self {
            ECDeviceError::InvalidAutoIncrementAddress { command, .. } => *command,
            ECDeviceError::InvalidConfiguredAddress { command, .. } => *command,
            ECDeviceError::InvalidWkc(d) => d.command,
            ECDeviceError::ESMError(d) => d.command,
        }
    }

    /// Returns a short diagnostic description for this specific error instance.
    pub fn diagnosis(&self) -> String {
        match self {
            ECDeviceError::InvalidAutoIncrementAddress { address, .. } => {
                format!(
                    "Auto-increment address {:#06x} does not map to any known device. \
                     Possible cause: device disconnected or topology change.",
                    address
                )
            }
            ECDeviceError::InvalidConfiguredAddress { address, .. } => {
                format!(
                    "Configured address {:#06x} not found in device map. \
                     Possible cause: device not yet configured or address conflict.",
                    address
                )
            }
            ECDeviceError::InvalidWkc(d) => {
                if d.actual == 0 {
                    format!(
                        "WKC=0 (expected {}): Complete communication failure — \
                         no device responded to {} command. \
                         Check: cable connections, device power, network topology.",
                        d.expected,
                        d.command.as_str()
                    )
                } else if d.actual < d.expected {
                    let missing = d.expected - d.actual;
                    format!(
                        "WKC={} (expected {}): {} device(s) did not respond to {} command. \
                         Partial failure — check individual device status and wiring.",
                        d.actual,
                        d.expected,
                        missing,
                        d.command.as_str()
                    )
                } else {
                    format!(
                        "WKC={} (expected {}): Unexpected extra responses to {} command. \
                         Possible address conflict or duplicate device configuration.",
                        d.actual,
                        d.expected,
                        d.command.as_str()
                    )
                }
            }
            ECDeviceError::ESMError(d) => {
                let base = match &d.error {
                    ESMError::IllegalTransition { to } => {
                        format!("Illegal state transition to {:?}.", to)
                    }
                    ESMError::InvalidStateTransition { requested, current } => {
                        format!(
                            "Invalid state transition: requested {:?} but device is in {:?}.",
                            requested, current
                        )
                    }
                    ESMError::BackwardTransition {
                        from,
                        to,
                        has_error,
                    } => {
                        let err_hint = if *has_error {
                            " Device reported an error flag."
                        } else {
                            ""
                        };
                        format!(
                            "Backward state transition {:?} → {:?}.{} \
                             The device may have encountered an internal fault.",
                            from, to, err_hint
                        )
                    }
                    ESMError::TransitionFailed {
                        requested,
                        current,
                        has_error,
                    } => {
                        let err_hint = if *has_error {
                            " Error flag is set."
                        } else {
                            ""
                        };
                        format!(
                            "State transition to {:?} failed; device stuck in {:?}.{} \
                             Check AL Status Code for details.",
                            requested, current, err_hint
                        )
                    }
                };
                format!("[{}] {}", d.subdevice_id, base)
            }
        }
    }
}

/// Represents a successful state transition observed on a subdevice.
#[derive(Debug, Clone)]
pub struct StateTransition {
    pub packet_number: u64,
    pub timestamp: Duration,
    pub subdevice_id: SubdeviceIdentifier,
    pub from: ECState,
    pub to: ECState,
}

#[derive(Debug)]
pub enum ECError {
    InvalidDatagram(ECPacketError),
    DeviceError(Vec<ECDeviceError>),
}

#[derive(Debug, Clone)]
pub struct ErrorCorrelation {
    pub wkc_error: WkcErrorDetail,
    pub esm_error: ESMErrorDetail,
    #[allow(dead_code)] // used in debug! logging
    pub frame_gap: u64,
}

pub struct DeviceManager {
    uninitialized: bool,
    num_frames: u64,
    expected_wkc: u16,
    devices: Vec<SubDevice>,
    config_address_map: HashMap<u16, usize>,
    wkc_error_history: VecDeque<WkcErrorDetail>,
    /// State transitions detected during the most recent analyze_packet call.
    pending_transitions: Vec<StateTransition>,
    /// Correlations detected during the most recent analyze_packet call.
    pending_correlations: Vec<ErrorCorrelation>,
}

impl DeviceManager {
    pub fn new() -> Self {
        DeviceManager {
            uninitialized: true,
            num_frames: 0,
            expected_wkc: 0,
            devices: Vec::new(),
            config_address_map: HashMap::new(),
            wkc_error_history: VecDeque::new(),
            pending_transitions: Vec::new(),
            pending_correlations: Vec::new(),
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

        // Snapshot device states before processing datagrams
        let states_before: Vec<(SubdeviceIdentifier, ECState)> = self
            .devices
            .iter()
            .map(|d| (d.identifier(), d.state()))
            .collect();

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
                    let err = ECDeviceError::InvalidAutoIncrementAddress {
                        packet_number,
                        timestamp,
                        command: datagram.command(),
                        address,
                    };
                    errors.push(err);
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
                    let err = ECDeviceError::InvalidConfiguredAddress {
                        packet_number,
                        timestamp,
                        command: datagram.command(),
                        address,
                    };
                    errors.push(err);
                }
                Err(ECDeviceError::InvalidWkc(wkc_err)) => {
                    warn!(
                        "#{} WKC error: {} [{}], adp {:04x}, ado {:#06x}, expected {}, got {}",
                        wkc_err.packet_number,
                        wkc_err.command.as_str(),
                        wkc_err
                            .subdevice_id
                            .unwrap_or(SubdeviceIdentifier::Unknown)
                            .to_string(),
                        datagram.address().0,
                        datagram.address().1,
                        wkc_err.expected,
                        wkc_err.actual,
                    );

                    let err = ECDeviceError::InvalidWkc(wkc_err);
                    self.wkc_error_history.push_back(wkc_err);
                    // Keep WKC history bounded
                    if self.wkc_error_history.len() > 200 {
                        self.wkc_error_history.pop_front();
                    }
                    errors.push(err);
                }
                Err(ECDeviceError::ESMError(esm_error)) => {
                    error!(
                        "#{} ESM Error [{}]: {:?}",
                        esm_error.packet_number, esm_error.subdevice_id, esm_error.error
                    );
                    let err = ECDeviceError::ESMError(esm_error);
                    errors.push(err);
                    self.correlate_esm_with_wkc(&esm_error);
                }
                _ => {}
            }
        }

        // Detect state transitions by comparing before/after snapshots
        for (i, (id, old_state)) in states_before.iter().enumerate() {
            if i < self.devices.len() {
                let new_state = self.devices[i].state();
                if new_state != *old_state {
                    self.pending_transitions.push(StateTransition {
                        packet_number: self.num_frames,
                        timestamp,
                        subdevice_id: *id,
                        from: *old_state,
                        to: new_state,
                    });
                }
            }
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(ECError::DeviceError(errors))
        }
    }

    /// Correlate ESM errors with recent WKC errors on the same device.
    fn correlate_esm_with_wkc(&mut self, esm_error: &ESMErrorDetail) {
        // Search backward through WKC history for matching subdevice
        let mut best_match: Option<(WkcErrorDetail, u64)> = None;

        for wkc_err in self.wkc_error_history.iter().rev() {
            if let Some(wkc_err_subdevice) = wkc_err.subdevice_id {
                if wkc_err_subdevice == esm_error.subdevice_id {
                    let gap = esm_error
                        .packet_number
                        .saturating_sub(wkc_err.packet_number);

                    // Prefer the closest (most recent) WKC error
                    match &best_match {
                        Some((_, existing_gap)) if gap >= *existing_gap => {}
                        _ => {
                            best_match = Some((*wkc_err, gap));
                        }
                    }
                    // The first match from the end is the closest, so we can break
                    break;
                }
            }
        }

        if let Some((wkc_err, gap)) = best_match {
            let correlation = ErrorCorrelation {
                wkc_error: wkc_err,
                esm_error: *esm_error,
                frame_gap: gap,
            };
            debug!(
                "Correlated ESM Error [{}] with WKC Error from frame #{} (gap: {} frames, time delta: {:.3}s)",
                esm_error.subdevice_id,
                wkc_err.packet_number,
                gap,
                (esm_error.timestamp.as_secs_f64() - wkc_err.timestamp.as_secs_f64()).abs()
            );
            self.pending_correlations.push(correlation);
        }
    }

    pub fn get_frame_count(&self) -> u64 {
        self.num_frames
    }

    /// Take any pending state transitions detected during the last analyze_packet call.
    /// This drains the internal buffer; each transition is returned only once.
    pub fn take_state_transitions(&mut self) -> Vec<StateTransition> {
        std::mem::take(&mut self.pending_transitions)
    }

    /// Take any pending correlations detected during the last analyze_packet call.
    /// This drains the internal buffer; each correlation is returned only once.
    pub fn take_pending_correlations(&mut self) -> Vec<ErrorCorrelation> {
        std::mem::take(&mut self.pending_correlations)
    }
}

impl Drop for DeviceManager {
    fn drop(&mut self) {
        debug!("Total analyzed EtherCAT frames: {}", self.num_frames);
        for (i, device) in self.devices.iter_mut().enumerate() {
            debug!("SubDevice {}: {}", i, device.identifier());
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

    fn process_fallback(&self, _manager: &mut DeviceManager, _datagram: &ECDatagram) {}

    fn uninitialized(&self, manager: &mut DeviceManager, _datagram: &ECDatagram) -> bool {
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
    fn get_idx_from_auto_increment_address(
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
        let subdevice_index = manager.config_address_map.get(&configured_address).ok_or(
            ECDeviceError::InvalidConfiguredAddress {
                packet_number: manager.num_frames,
                timestamp: self.timestamp,
                command: datagram.command(),
                address: configured_address,
            },
        )?;

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
        let subdevice_index = manager.config_address_map.get(&configured_address).ok_or(
            ECDeviceError::InvalidConfiguredAddress {
                packet_number: manager.num_frames,
                timestamp: self.timestamp,
                command: datagram.command(),
                address: configured_address,
            },
        )?;
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

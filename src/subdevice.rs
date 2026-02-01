use crate::registers::{AlControl, AlStatus, RegisterAddress};
use std::collections::BTreeMap;

use log::debug;

#[derive(Debug, Default, Copy, Clone, PartialEq, Eq)]
#[repr(u8)]
pub enum ECState {
    #[default]
    Init = 0x01,
    PreOp = 0x02,
    SafeOp = 0x04,
    Op = 0x08,
    Bootstrap = 0x03,
}

pub enum ESMError {
    InvalidTransition,
}

pub struct SubDevice {
    state: ECState,
    configured_address: Option<u16>,
    al_status: Option<AlStatus>,
    al_status_code: Option<u16>,
    al_control: Option<AlControl>,
    register_brd: BTreeMap<u16, u8>,
    register_wr: BTreeMap<u16, u8>,
    register_rd: BTreeMap<u16, u8>,
}

impl SubDevice {
    pub fn new() -> Self {
        SubDevice {
            state: ECState::Init,
            configured_address: None,
            al_status: None,
            al_status_code: None,
            al_control: None,
            register_brd: BTreeMap::new(),
            register_wr: BTreeMap::new(),
            register_rd: BTreeMap::new(),
        }
    }

    pub fn configured_address(&self) -> Option<u16> {
        self.configured_address
    }

    pub fn configured_alias(&self) -> Option<u16> {
        let mut iter = self.read_reg_wr(RegisterAddress::ConfiguredStationAlias, 2);
        let low = iter.next().flatten()?;
        let high = iter.next().flatten()?;
        Some(u16::from_le_bytes([low, high]))
    }

    fn write_reg_impl(register: &mut BTreeMap<u16, u8>, reg_addr: u16, data: &[u8]) {
        for (i, value) in data.iter().enumerate() {
            register.insert(reg_addr.wrapping_add(i as u16), *value);
        }
    }

    fn read_reg_impl(
        register: &BTreeMap<u16, u8>,
        reg_addr: u16,
        length: u16,
    ) -> impl Iterator<Item = Option<u8>> {
        (0..length).map(move |i| register.get(&reg_addr.wrapping_add(i)).cloned())
    }

    pub fn write_reg_wr(&mut self, reg_addr: u16, data: &[u8]) {
        Self::write_reg_impl(&mut self.register_wr, reg_addr, data);
        self.configured_address = self.load_configured_address();
    }

    pub fn read_reg_wr(&self, reg_addr: u16, length: u16) -> impl Iterator<Item = Option<u8>> {
        Self::read_reg_impl(&self.register_wr, reg_addr, length)
    }

    pub fn write_reg_rd(&mut self, reg_addr: u16, data: &[u8]) {
        Self::write_reg_impl(&mut self.register_rd, reg_addr, data);
    }

    pub fn read_reg_rd(&self, reg_addr: u16, length: u16) -> impl Iterator<Item = Option<u8>> {
        Self::read_reg_impl(&self.register_rd, reg_addr, length)
    }

    pub fn write_reg_brd(&mut self, reg_addr: u16, data: &[u8]) {
        Self::write_reg_impl(&mut self.register_brd, reg_addr, data);
    }

    pub fn read_reg_brd(&self, reg_addr: u16, length: u16) -> impl Iterator<Item = Option<u8>> {
        Self::read_reg_impl(&self.register_brd, reg_addr, length)
    }

    fn load_configured_address(&self) -> Option<u16> {
        if self.configured_address.is_none() {
            let configued_address = {
                let mut iter = self.read_reg_wr(RegisterAddress::ConfiguredStationAddress, 2);
                let low = iter.next().flatten()?;
                let high = iter.next().flatten()?;
                u16::from_le_bytes([low, high])
            };
            Some(configued_address)
        } else {
            self.configured_address
        }
    }

    pub fn state_machine_step<T: CommandStepper>(&mut self, packet_num: u64) {
        T::execute(self, packet_num);
    }
}

pub trait CommandStepper {
    fn execute(subdevice: &mut SubDevice, packet_num: u64) {
        match subdevice.state {
            ECState::Init => {
                let _ = Self::init(subdevice);
            }
            ECState::PreOp => {
                let _ = Self::preop(subdevice);
            }
            ECState::SafeOp => {
                let _ = Self::safeop(subdevice);
            }
            ECState::Op => {
                let _ = Self::op(subdevice);
            }
            ECState::Bootstrap => {
                // No transitions defined yet
            }
        }
        Self::common(subdevice);

        Self::change_state(subdevice, packet_num);
    }

    fn init(_subdevice: &mut SubDevice) -> Option<()> {
        Some(())
    }
    fn preop(_subdevice: &mut SubDevice) -> Option<()> {
        Some(())
    }
    fn safeop(_subdevice: &mut SubDevice) -> Option<()> {
        Some(())
    }
    fn op(_subdevice: &mut SubDevice) -> Option<()> {
        Some(())
    }
    fn common(_subdevice: &mut SubDevice) -> Option<()> {
        Some(())
    }

    fn change_state(subdevice: &mut SubDevice, packet_num: u64) -> Option<()> {
        if let Some(al_status) = subdevice.al_status {
            if let Ok(new_state) = al_status.state {
                if subdevice.state != new_state {
                    debug!(
                        "#{} SubDevice {:04x} state changed from {:?} to {:?}",
                        packet_num,
                        subdevice
                            .configured_address()
                            .map(|addr| addr as i32)
                            .unwrap_or(-1),
                        subdevice.state,
                        new_state
                    );
                    subdevice.state = new_state;
                }
            }
            if al_status.error {
                let al_status_code = {
                    let mut iter = subdevice.read_reg_rd(RegisterAddress::AlStatusCode, 2);
                    let low = iter.next().flatten();
                    let high = iter.next().flatten();
                    if let (Some(low), Some(high)) = (low, high) {
                        Some(u16::from_le_bytes([low, high]))
                    } else {
                        None
                    }
                };
                subdevice.al_status_code = al_status_code;
            } else {
                subdevice.al_status_code = None;
            }
        }

        Some(())
    }
}

pub struct BrdCommandStepper;
impl CommandStepper for BrdCommandStepper {
    fn common(subdevice: &mut SubDevice) -> Option<()> {
        let al_control = {
            let mut iter = subdevice.read_reg_wr(RegisterAddress::AlControl, 1);
            iter.next().flatten().map(|b| AlControl::new(b))
        };
        subdevice.al_control = al_control;

        let al_status = {
            let mut iter = subdevice.read_reg_brd(RegisterAddress::AlStatus, 1);
            iter.next().flatten().map(|b| AlStatus::new(b))
        };
        if let Some(al_status) = al_status
            && al_status.state.is_ok()
        {
            subdevice.al_status = Some(al_status);
        }

        Some(())
    }
}

pub struct AprdCommandStepper;
impl CommandStepper for AprdCommandStepper {
    fn init(subdevice: &mut SubDevice) -> Option<()> {
        if subdevice.configured_address.is_none() {
            let configued_address_wr = {
                let mut iter = subdevice.read_reg_wr(RegisterAddress::ConfiguredStationAddress, 2);
                let low = iter.next().flatten()?;
                let high = iter.next().flatten()?;
                u16::from_le_bytes([low, high])
            };
            let configued_address_rd = {
                let mut iter = subdevice.read_reg_rd(RegisterAddress::ConfiguredStationAddress, 2);
                let low = iter.next().flatten()?;
                let high = iter.next().flatten()?;
                u16::from_le_bytes([low, high])
            };
            if configued_address_wr != configued_address_rd {
                return None;
            }
            subdevice.configured_address = Some(configued_address_wr);
        }

        Some(())
    }
}

pub struct FprdCommandStepper;
impl CommandStepper for FprdCommandStepper {
    fn common(subdevice: &mut SubDevice) -> Option<()> {
        let al_control = {
            let mut iter = subdevice.read_reg_wr(RegisterAddress::AlControl, 1);
            iter.next().flatten().map(|b| AlControl::new(b))
        };
        subdevice.al_control = al_control;

        let al_status = {
            let mut iter = subdevice.read_reg_rd(RegisterAddress::AlStatus, 1);
            iter.next().flatten().map(|b| AlStatus::new(b))
        };
        subdevice.al_status = al_status;

        Some(())
    }
}

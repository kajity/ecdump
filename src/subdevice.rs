use std::ops::Sub;

use crate::ec_packet::{ECDatagram, ECDatagramView};
use log::debug;

pub enum ECState {
    Init,
    PreOp,
    SafeOp,
    Op,
}

impl Default for ECState {
    fn default() -> Self {
        ECState::Init
    }
}

pub struct SubDevice {
    configured_address: u16,
    configured_alias: u16,
    physical_address: u16,
    state: ECState,
}

impl SubDevice {
    pub fn new() -> Self {
        SubDevice {
            configured_address: 0,
            configured_alias: 0,
            physical_address: 0,
            state: ECState::Init,
        }
    }

    pub fn process(&mut self, datagram: &ECDatagram, from_main: bool) {
        match self.state {
            ECState::Init => {
                // if datagram.command() == 0x02 {
                //     // APRD
                //     debug!("Handling APRD in INIT state");
                //     // Here you would add logic to handle the APRD command in INIT state
                //     // For example, you might want to change the state based on certain conditions
                //     *state = ECState::PreOP;
                // }
                self.handle_ethercat_datagram_init(&datagram);
            }
            ECState::PreOp => {
                debug!("In PRE-OP state, no specific handling implemented yet");
                // Add handling for PRE-OP state if needed
            }
            ECState::SafeOp => {
                debug!("In SAFE-OP state, no specific handling implemented yet");
                // Add handling for SAFE-OP state if needed
            }
            ECState::Op => {
                debug!("In OP state, no specific handling implemented yet");
                // Add handling for OP state if needed
            }
        }
    }

    fn handle_ethercat_datagram_init(&self, datagram: &ECDatagram) {
        // datagram.inc_wkc().inc_autoincrement_address();
    }
}

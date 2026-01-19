use crate::ec_packet::{ECDatagramView, ECPacketView};
use log::debug;

pub enum ECState {
    Init,
    PreOp,
    SafeOp,
    Op,
}

pub struct ECStateMachine {
    state: ECState,
}

impl Default for ECState {
    fn default() -> Self {
        ECState::Init
    }
}

impl ECStateMachine {
    pub fn new() -> Self {
        ECStateMachine {
            state: ECState::Init,
        }
    }

    pub fn next(&mut self, datagram: &mut ECPacketView) {
        let mut datagram_view = ECDatagramView::new(datagram.payload()).unwrap();
        match self.state {
            ECState::Init => {
                // if datagram.command() == 0x02 {
                //     // APRD
                //     debug!("Handling APRD in INIT state");
                //     // Here you would add logic to handle the APRD command in INIT state
                //     // For example, you might want to change the state based on certain conditions
                //     *state = ECState::PreOP;
                // }
                self.handle_ethercat_datagram_init(&mut datagram_view);
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

    fn handle_ethercat_datagram_init(&self, datagram: &mut ECDatagramView) {
        datagram.inc_wkc().inc_autoincrement_address();
    }
}

pub struct SubDevice {
    configured_address: u16,
    physical_address: u16,
    state: ECStateMachine,
}

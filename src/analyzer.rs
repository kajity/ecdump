use crate::ec_packet::ECPacket;
use ecdump::subdevice::SubDevice;

pub struct DeviceManager {
    devices: Vec<SubDevice>,
}

impl DeviceManager {
    pub fn new() -> Self {
        DeviceManager {
            devices: Vec::new(),
        }
    }

    pub fn analyze_packet(&mut self, packet: &mut ECPacket) {
        // let command = packet.get_command();
        // for device in &mut self.devices {
        //     // Here you would add logic to analyze the packet for each device
        //     // For example, checking addresses, commands, etc.
        // }
    }
}

use log::debug;

pub enum EtherCATState {
    Init,
    PreOP,
    SafeOP,
    OP,
}

pub struct EtherCATStateMachine {
    state: EtherCATState,
}

impl Default for EtherCATState {
    fn default() -> Self {
        EtherCATState::Init
    }
}

#[derive(Debug)]
pub struct EtherCATPacket<'a> {
    length: u16,
    type_field: u8,
    payload: &'a [u8],
}

pub struct EtherCATPacketView<'a> {
    data: &'a mut [u8],
}

/// Representation of EtherCAT Addressing Modes
///
/// Device Addressing
///   Position Address / Auto Increment Address:
///     The datagram holds the position address of the addressed slave as a negative value. Each slave
///     increments the address. The slave which reads the address equal zero is addressed and will
///     execute the appropriate command at receive.
///     Position Addressing should only be used during start-up of the EtherCAT system to scan the
///     fieldbus and later only occasionally to detect newly attached slaves. Using Position addressing is
///     problematic if loops are closed temporarily due to hot connecting or link problems. Position
///     addresses are shifted in this case, and e.g., a mapping of error register values to devices
///     becomes impossible, thus the faulty link cannot be localized.
///   Node Address / Configured Station Address and Configured Station Alias:
///     The configured Station Address is assigned by the master during start up and cannot be changed
///     by the EtherCAT slave. The Configured Station Alias address is stored in the SII EEPROM and
///     can be changed by the EtherCAT slave. The Configured Station Alias has to be enabled by the
///     master. The appropriate command action will be executed if Node Address matches with either
///     Configured Station Address or Configured Station Alias.
///     Node addressing is typically used for register access to individual and already identified devices.
///   Broadcast:
///     Each EtherCAT slave is addressed.
///     Broadcast addressing is used e.g. for initialization of all slaves and for checking the status of all
///     slaves if they are expected to be identical.
/// Logical Addressing
///     All devices read from and write to the same logical 4 Gbyte address space (32 bit address field within
///     the EtherCAT datagram). A slave uses a mapping unit (FMMU, Fieldbus Memory Management Unit)
///     to map data from the logical process data image to its local address space. During start up the master
///     configures the FMMUs of each slave. The slave knows which parts of the logical process data image
///     have to be mapped to which local address space using the configuration information of the FMMUs.
///     Logical Addressing supports bit wise mapping. Logical Addressing is a powerful mechanism to reduce
///     the overhead of process data communication, thus it is typically used for accessing process data.
pub enum EtherCATAddress {
    Position { adp: u16, ado: u16 }, // Auto Increment address, Broadcast
    Node { address: u16, offset: u16 },     // Configured Station Address/Configured Station Alias
    Logical(u32),                           //
}

#[derive(Debug)]
pub struct EtherCATDatagram<'a> {
    command: u8,
    index: u8,
    address: u32,
    length: u16,
    circular: bool,
    more: bool,
    irq: u16,
    payload: &'a [u8],
    wkc: u16,
}

pub struct EtherCATDatagramView<'a> {
    data: &'a mut [u8],
    data_len: usize,
}

impl<'a> EtherCATPacket<'a> {
    pub fn new(data: &'a [u8]) -> Option<EtherCATPacket<'a>> {
        if data.len() < 2 {
            return None;
        }
        // debug!("parsing {:02x?}", data);
        // header: | type (4 bits) | reserved (1 bit) | length (11 bits) |
        let header = u16::from_le_bytes([data[0], data[1]]);
        let length = header & 0x07FF;
        let type_field = ((header & 0xF000) >> 12) as u8;
        let payload = &data[2..];
        Some(EtherCATPacket {
            length,
            type_field,
            payload,
        })
    }

    pub fn datagram_length(&self) -> u16 {
        self.length
    }
    pub fn protocol_type(&self) -> u8 {
        self.type_field
    }
    pub fn payload(&self) -> &'a [u8] {
        self.payload
    }
}

impl<'a> EtherCATDatagram<'a> {
    pub fn new(data: &'a [u8]) -> Option<EtherCATDatagram<'a>> {
        if data.len() < 10 {
            return None;
        }
        let command = data[0];
        let index = data[1];
        let address = u32::from_le_bytes([data[2], data[3], data[4], data[5]]);
        // | more (1 bit) | circular (1 bit) | reserved (3 bits) | irq (11 bits) |
        let info = u16::from_le_bytes([data[6], data[7]]);
        let length = info & 0x07FF;
        if length as usize + 10 + 2 > data.len() {
            return None;
        }
        let circular = (info & 0x4000) != 0;
        let more = (info & 0x8000) != 0;
        let irq = u16::from_le_bytes([data[8], data[9]]);
        let payload = &data[10..(10 + length as usize)];
        let wkc_offset = 10 + length as usize;
        if data.len() < wkc_offset + 2 {
            return None;
        }
        let wkc = u16::from_le_bytes([data[wkc_offset], data[wkc_offset + 1]]);

        Some(EtherCATDatagram {
            command,
            index,
            address,
            length,
            circular,
            more,
            irq,
            payload,
            wkc,
        })
    }

    pub fn command(&self) -> u8 {
        self.command
    }
    pub fn index(&self) -> u8 {
        self.index
    }
    pub fn address(&self) -> u32 {
        self.address
    }
    pub fn length(&self) -> u16 {
        self.length
    }
    pub fn payload(&self) -> &'a [u8] {
        self.payload
    }
    pub fn is_circular(&self) -> bool {
        self.circular
    }
    pub fn has_more(&self) -> bool {
        self.more
    }
    pub fn irq(&self) -> u16 {
        self.irq
    }
    pub fn wkc(&self) -> u16 {
        self.wkc
    }
    pub fn command_str(&self) -> &'static str {
        match self.command {
            0x0 => "NOP",  // No Operation
            0x1 => "APRD", // Auto Increment Physical Read
            0x2 => "APWR", // Auto Increment Physical Write
            0x3 => "APRW", // Auto Increment Physical Read/Write
            0x4 => "FPRD", // Configured Address Physical Read
            0x5 => "FPWR", // Configured Address Physical Write
            0x6 => "FPRW", // Configured Address Physical Read/Write
            0x7 => "BRD",  // Broadcast Read
            0x8 => "BWR",  // Broadcast Write
            0x9 => "BRW",  // Broadcast Read/Write
            0xA => "LRD",  // Logical Memory Read
            0xB => "LWR",  // Logical Memory Write
            0xC => "LRW",  // Logical Memory Read/Write
            0xD => "ARMW", // Auto Increment Physical Read Modify Write
            0xE => "FRMW", // Configured Address Physical Read Modify Write
            _ => "UNKNOWN",
        }
    }
}

impl<'a> EtherCATPacketView<'a> {
    pub fn new(data: &'a mut [u8]) -> Option<EtherCATPacketView<'a>> {
        if data.len() < 2 {
            return None;
        }
        Some(EtherCATPacketView { data })
    }
    pub fn payload(&mut self) -> &mut [u8] {
        &mut self.data[2..]
    }
}

impl<'a> EtherCATDatagramView<'a> {
    pub fn new(data: &'a mut [u8]) -> Option<EtherCATDatagramView<'a>> {
        if data.len() < 10 {
            return None;
        }
        let data_len = u16::from_le_bytes([data[6], data[7]]) & 0x07FF;
        if data.len() < (10 + data_len as usize + 2) {
            return None;
        }
        Some(EtherCATDatagramView {
            data,
            data_len: data_len as usize,
        })
    }
    pub fn payload(&mut self) -> &mut [u8] {
        &mut self.data[10..(10 + self.data_len)]
    }
    pub fn wkc(&self) -> u16 {
        let wkc_offset = 10 + self.data_len;
        u16::from_le_bytes([self.data[wkc_offset], self.data[wkc_offset + 1]])
    }
    pub fn command(&self) -> u8 {
        self.data[0]
    }

    pub fn inc_wkc(&mut self) -> &mut Self {
        let wkc_offset = 10 + self.data_len;
        let wkc = u16::from_le_bytes([self.data[wkc_offset], self.data[wkc_offset + 1]]);
        let new_wkc = wkc.wrapping_add(1);
        let new_wkc_bytes = new_wkc.to_le_bytes();
        self.data[wkc_offset] = new_wkc_bytes[0];
        self.data[wkc_offset + 1] = new_wkc_bytes[1];

        self
    }

    pub fn inc_autoincrement_address(&mut self) -> &mut Self {
        let address_offset = 2;
        let address =
            u16::from_le_bytes([self.data[address_offset], self.data[address_offset + 1]]);
        let new_address = address.wrapping_add(1);
        let new_address_bytes = new_address.to_le_bytes();
        self.data[address_offset] = new_address_bytes[0];
        self.data[address_offset + 1] = new_address_bytes[1];

        self
    }
}

impl EtherCATStateMachine {
    pub fn new() -> Self {
        EtherCATStateMachine {
            state: EtherCATState::Init,
        }
    }

    pub fn next(&mut self, datagram: &mut EtherCATPacketView) {
        let mut datagram_view = EtherCATDatagramView::new(datagram.payload()).unwrap();
        match self.state {
            EtherCATState::Init => {
                // if datagram.command() == 0x02 {
                //     // APRD
                //     debug!("Handling APRD in INIT state");
                //     // Here you would add logic to handle the APRD command in INIT state
                //     // For example, you might want to change the state based on certain conditions
                //     *state = EtherCATState::PreOP;
                // }
                self.handle_ethercat_datagram_init(&mut datagram_view);
            }
            EtherCATState::PreOP => {
                debug!("In PRE-OP state, no specific handling implemented yet");
                // Add handling for PRE-OP state if needed
            }
            EtherCATState::SafeOP => {
                debug!("In SAFE-OP state, no specific handling implemented yet");
                // Add handling for SAFE-OP state if needed
            }
            EtherCATState::OP => {
                debug!("In OP state, no specific handling implemented yet");
                // Add handling for OP state if needed
            }
        }
    }

    fn handle_ethercat_datagram_init(&self, datagram: &mut EtherCATDatagramView) {
        datagram.inc_wkc().inc_autoincrement_address();
    }
}

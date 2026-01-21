use log::warn;
use smallvec::SmallVec;

#[derive(Debug)]
pub enum ECPacketError {
    InvalidHeader,
    InvalidDatalength,
}

#[derive(Debug)]
pub struct ECFrame<'a> {
    total_length: u16,
    type_field: u8,
    payload: &'a [u8],
}

pub struct ECFrameView<'a> {
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
pub enum ECAddress {
    Position { adp: u16, ado: u16 }, // Auto Increment address, Broadcast
    Node { address: u16, offset: u16 }, // Configured Station Address/Configured Station Alias
    Logical(u32),                    // Logical Addressing
}

#[derive(Debug, Clone, Copy)]
pub struct ECCommandType(u8);
impl ECCommandType {
    pub fn as_str(&self) -> &'static str {
        match self.0 {
            ECCommand::NOP => "NOP",   // No Operation
            ECCommand::APRD => "APRD", // Auto Increment Physical Read
            ECCommand::APWR => "APWR", // Auto Increment Physical Write
            ECCommand::APRW => "APRW", // Auto Increment Physical Read/Write
            ECCommand::FPRD => "FPRD", // Configured Address Physical Read
            ECCommand::FPWR => "FPWR", // Configured Address Physical Write
            ECCommand::FPRW => "FPRW", // Configured Address Physical Read/Write
            ECCommand::BRD => "BRD",   // Broadcast Read
            ECCommand::BWR => "BWR",   // Broadcast Write
            ECCommand::BRW => "BRW",   // Broadcast Read/Write
            ECCommand::LRD => "LRD",   // Logical Memory Read
            ECCommand::LWR => "LWR",   // Logical Memory Write
            ECCommand::LRW => "LRW",   // Logical Memory Read/Write
            ECCommand::ARMW => "ARMW", // Auto Increment Physical Read Modify Write
            ECCommand::FRMW => "FRMW", // Configured Address Physical Read Modify Write
            _ => "UNKNOWN",
        }
    }
}

pub struct ECDatagrams<'a> {
    inner: SmallVec<[ECDatagram<'a>; 1]>,
}

impl<'a> ECDatagrams<'a> {
    pub fn iter(&self) -> impl Iterator<Item = &ECDatagram<'a>> {
        self.inner.iter()
    }
}

#[derive(Debug)]
pub struct ECDatagram<'a> {
    command: ECCommandType,
    index: u8,
    address: u32,
    length: u16,
    circular: bool,
    more: bool,
    irq: u16,
    payload: &'a [u8],
    wkc: u16,
}

pub struct ECDatagramView<'a> {
    data: &'a mut [u8],
    data_len: usize,
}

impl<'a> ECFrame<'a> {
    pub fn new(data: &'a [u8]) -> Option<ECFrame<'a>> {
        if data.len() < 2 {
            return None;
        }
        // debug!("parsing {:02x?}", data);
        // header: | type (4 bits) | reserved (1 bit) | length (11 bits) |
        let header = u16::from_le_bytes([data[0], data[1]]);
        let total_length = header & 0x07FF;
        let type_field = ((header & 0xF000) >> 12) as u8;
        let payload = &data[2..];
        Some(ECFrame {
            total_length,
            type_field,
            payload,
        })
    }

    pub fn datagram_length(&self) -> u16 {
        self.total_length
    }
    pub fn protocol_type(&self) -> u8 {
        self.type_field
    }
    pub fn payload(&self) -> &'a [u8] {
        self.payload
    }
    pub fn parse_datagram(&self) -> Result<ECDatagrams<'a>, ECPacketError> {
        let mut datagrams = SmallVec::<[ECDatagram<'a>; 1]>::new();
        let mut remaining_length = self.total_length;
        while remaining_length > 0 {
            match ECDatagram::new(
                &self.payload[(self.total_length - remaining_length) as usize..],
                remaining_length,
            )? {
                Some(datagram) => {
                    remaining_length -= 10 + datagram.length + 2;
                    datagrams.push(datagram);
                }
                None => {
                    break;
                }
            }
        }
        if remaining_length != 0 || datagrams.is_empty() {
            return Err(ECPacketError::InvalidHeader);
        }
        Ok(ECDatagrams { inner: datagrams })
    }
}

impl<'a> ECDatagram<'a> {
    pub fn new(data: &'a [u8], total_length: u16) -> Result<Option<ECDatagram<'a>>, ECPacketError> {
        if total_length == 0 {
            return Ok(None);
        }
        if data.len() < 10 {
            return Err(ECPacketError::InvalidDatalength);
        }
        let command = data[0];
        let index = data[1];
        let address = u32::from_le_bytes([data[2], data[3], data[4], data[5]]);
        // | more (1 bit) | circular (1 bit) | reserved (3 bits) | irq (11 bits) |
        let info = u16::from_le_bytes([data[6], data[7]]);
        let length = info & 0x07FF;
        if length as usize + 10 + 2 > data.len() || length + 10 + 2 > total_length {
            return Err(ECPacketError::InvalidDatalength);
        }
        let circular = (info & 0x4000) != 0;
        let more = (info & 0x8000) != 0;
        let irq = u16::from_le_bytes([data[8], data[9]]);
        let payload = &data[10..(10 + length as usize)];
        let wkc_offset = 10 + length as usize;
        let wkc = u16::from_le_bytes([data[wkc_offset], data[wkc_offset + 1]]);

        Ok(Some(ECDatagram {
            command: ECCommandType(command),
            index,
            address,
            length,
            circular,
            more,
            irq,
            payload,
            wkc,
        }))
    }

    pub fn command(&self) -> ECCommandType {
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
}

impl<'a> ECFrameView<'a> {
    pub fn new(data: &'a mut [u8]) -> Option<ECFrameView<'a>> {
        if data.len() < 2 {
            return None;
        }
        Some(ECFrameView { data })
    }
    pub fn payload(&mut self) -> &mut [u8] {
        &mut self.data[2..]
    }
}

impl<'a> ECDatagramView<'a> {
    pub fn new(data: &'a mut [u8]) -> Option<ECDatagramView<'a>> {
        if data.len() < 10 {
            return None;
        }
        let data_len = u16::from_le_bytes([data[6], data[7]]) & 0x07FF;
        if data.len() < (10 + data_len as usize + 2) {
            return None;
        }
        Some(ECDatagramView {
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

#[allow(non_snake_case)]
#[allow(non_upper_case_globals)]
pub mod ECCommand {
    pub const NOP: u8 = 0x00; // No Operation
    pub const APRD: u8 = 0x01; // Auto Increment Physical Read
    pub const APWR: u8 = 0x02; // Auto Increment Physical Write
    pub const APRW: u8 = 0x03; // Auto Increment Physical Read/Write
    pub const FPRD: u8 = 0x04; // Configured Address Physical Read
    pub const FPWR: u8 = 0x05; // Configured Address Physical Write
    pub const FPRW: u8 = 0x06; // Configured Address Physical Read/Write
    pub const BRD: u8 = 0x07; // Broadcast Read
    pub const BWR: u8 = 0x08; // Broadcast Write
    pub const BRW: u8 = 0x09; // Broadcast Read/Write
    pub const LRD: u8 = 0x0A; // Logical Memory Read
    pub const LWR: u8 = 0x0B; // Logical Memory Write
    pub const LRW: u8 = 0x0C; // Logical Memory Read/Write
    pub const ARMW: u8 = 0x0D; // Auto Increment Physical Read Modify Write
    pub const FRMW: u8 = 0x0E; // Configured Address Physical Read Modify Write
}

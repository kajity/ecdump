use std::{collections::BTreeMap, time::Duration};

use crate::ec_packet::{ECCommands, ECDatagram, ECDatagramView};
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
    idx: u16,
    wkc_expected: u16,
    state: ECState,
    register: BTreeMap<u16, u8>,
}

impl SubDevice {
    pub fn new(idx: u16) -> Self {
        SubDevice {
            idx,
            wkc_expected: 0,
            state: ECState::Init,
            register: BTreeMap::new(),
        }
    }

    pub fn configured_address(&self) -> Option<u16> {
        let mut iter = self.read_reg(RegisterAddress::ConfiguredStationAddress, 2);
        let low = iter.next().flatten()?;
        let high = iter.next().flatten()?;
        Some(u16::from_le_bytes([low, high]))
    }

    pub fn write_reg(&mut self, reg_addr: u16, data: &[u8]) {
        for (i, value) in data.iter().enumerate() {
            self.register
                .insert(reg_addr.wrapping_add(i as u16), *value);
        }
    }

    fn read_reg(&self, reg_addr: u16, length: u16) -> impl Iterator<Item = Option<u8>> {
        (0..length).map(move |i| self.register.get(&reg_addr.wrapping_add(i)).cloned())
    }
}

#[allow(non_snake_case)]
#[allow(non_upper_case_globals)]
#[allow(dead_code)]
pub mod RegisterAddress {
    /// Type, `u8`.
    pub const Type: u16 = 0x0000;
    /// EtherCAT revision.
    pub const Revision: u16 = 0x0001;
    /// SubDevice build.
    pub const Build: u16 = 0x0002;
    /// Number of supported FMMU entities.
    pub const FmmuCount: u16 = 0x0004;
    /// Number of supported sync manager channels.
    pub const SyncManagerChannels: u16 = 0x0005;
    /// RAM size in kilo-octets (1024 octets)
    pub const RamSize: u16 = 0x0006;
    /// EtherCAT port descriptors 0-3, `u8`.
    pub const PortDescriptors: u16 = 0x0007;
    /// Different EtherCAT features supported by the SubDevice, `u16`.
    pub const SupportFlags: u16 = 0x0008;
    /// The SubDevice's configured station address, `u16`.
    pub const ConfiguredStationAddress: u16 = 0x0010;
    /// The SubDevice's address alias, `u16`.
    pub const ConfiguredStationAlias: u16 = 0x0012;

    /// Defined in ETG1000.4 Table 34 - DL status, `u16`.
    pub const DlStatus: u16 = 0x0110;

    // AKA DLS-user R1, `u8`.
    /// Application Layer (AL) control register. See ETG1000.4 Table 35.
    pub const AlControl: u16 = 0x0120;
    // AKA DLS-user R3, `u8`.
    /// Application Layer (AL) status register. See ETG1000.4 Table 35.
    pub const AlStatus: u16 = 0x0130;
    // AKA DLS-user R6, `u16`.
    /// Application Layer (AL) status code register.
    pub const AlStatusCode: u16 = 0x0134;

    /// Watchdog divider, `u16`.
    ///
    /// See ETG1000.4 section 6.3 Watchdogs.
    pub const WatchdogDivider: u16 = 0x0400;

    /// PDI watchdog timeout, `u16`.
    pub const PdiWatchdog: u16 = 0x0410;

    /// Sync manager watchdog timeout, `u16`.
    pub const SyncManagerWatchdog: u16 = 0x0420;

    /// Sync manager watchdog status (1 bit), `u16`.
    pub const SyncManagerWatchdogStatus: u16 = 0x0440;

    /// Sync manager watchdog counter, `u8`.
    pub const SyncManagerWatchdogCounter: u16 = 0x0442;
    /// PDI watchdog counter, `u8`.
    pub const PdiWatchdogCounter: u16 = 0x0443;

    /// EEPROM (SII) config register, `u16`.
    pub const SiiConfig: u16 = 0x0500;

    /// EEPROM (SII) control register, `u16`.
    pub const SiiControl: u16 = 0x0502;

    /// EEPROM (SII) control address, `u16`.
    pub const SiiAddress: u16 = 0x0504;
    /// The start of 4 bytes (read) or 2 bytes (write) of data used by the EEPROM read/write `writing`.
    /// interface.
    pub const SiiData: u16 = 0x0508;

    /// Fieldbus Memory Management Unit (FMMU) 0.
    ///
    /// Defined in ETG1000.4 Table 57
    pub const Fmmu0: u16 = 0x0600;
    /// Fieldbus Memory Management Unit (FMMU) 1.
    pub const Fmmu1: u16 = 0x0610;
    /// Fieldbus Memory Management Unit (FMMU) 2.
    pub const Fmmu2: u16 = 0x0620;
    /// Fieldbus Memory Management Unit (FMMU) 3.
    pub const Fmmu3: u16 = 0x0630;
    /// Fieldbus Memory Management Unit (FMMU) 4.
    pub const Fmmu4: u16 = 0x0640;
    /// Fieldbus Memory Management Unit (FMMU) 5.
    pub const Fmmu5: u16 = 0x0650;
    /// Fieldbus Memory Management Unit (FMMU) 6.
    pub const Fmmu6: u16 = 0x0660;
    /// Fieldbus Memory Management Unit (FMMU) 7.
    pub const Fmmu7: u16 = 0x0670;
    /// Fieldbus Memory Management Unit (FMMU) 8.
    pub const Fmmu8: u16 = 0x0680;
    /// Fieldbus Memory Management Unit (FMMU) 9.
    pub const Fmmu9: u16 = 0x0690;
    /// Fieldbus Memory Management Unit (FMMU) 10.
    pub const Fmmu10: u16 = 0x06A0;
    /// Fieldbus Memory Management Unit (FMMU) 11.
    pub const Fmmu11: u16 = 0x06B0;
    /// Fieldbus Memory Management Unit (FMMU) 12.
    pub const Fmmu12: u16 = 0x06C0;
    /// Fieldbus Memory Management Unit (FMMU) 13.
    pub const Fmmu13: u16 = 0x06D0;
    /// Fieldbus Memory Management Unit (FMMU) 14.
    pub const Fmmu14: u16 = 0x06E0;
    /// Fieldbus Memory Management Unit (FMMU) 15.
    pub const Fmmu15: u16 = 0x06F0;

    /// Sync Manager (SM) 0.
    ///
    /// Defined in ETG1000.4 Table 59.
    pub const Sm0: u16 = 0x0800;
    /// Sync Manager (SM) 1.
    pub const Sm1: u16 = 0x0808;
    /// Sync Manager (SM) 2.
    pub const Sm2: u16 = 0x0810;
    /// Sync Manager (SM) 3.
    pub const Sm3: u16 = 0x0818;
    /// Sync Manager (SM) 4.
    pub const Sm4: u16 = 0x0820;
    /// Sync Manager (SM) 5.
    pub const Sm5: u16 = 0x0828;
    /// Sync Manager (SM) 6.
    pub const Sm6: u16 = 0x0830;
    /// Sync Manager (SM) 7.
    pub const Sm7: u16 = 0x0838;
    /// Sync Manager (SM) 8.
    pub const Sm8: u16 = 0x0840;
    /// Sync Manager (SM) 9.
    pub const Sm9: u16 = 0x0848;
    /// Sync Manager (SM) 10.
    pub const Sm10: u16 = 0x0850;
    /// Sync Manager (SM) 11.
    pub const Sm11: u16 = 0x0858;
    /// Sync Manager (SM) 12.
    pub const Sm12: u16 = 0x0860;
    /// Sync Manager (SM) 13.
    pub const Sm13: u16 = 0x0868;
    /// Sync Manager (SM) 14.
    pub const Sm14: u16 = 0x0870;
    /// Sync Manager (SM) 15.
    pub const Sm15: u16 = 0x0878;

    /// Distributed clock (DC) port 0 receive time in ns.
    ///
    /// Distributed clock registers are defined in ETG1000.4 Table 60.
    pub const DcTimePort0: u16 = 0x0900;
    /// Distributed clock (DC) port 1 receive time in ns.
    pub const DcTimePort1: u16 = 0x0904;
    /// Distributed clock (DC) port 2 receive time in ns.
    pub const DcTimePort2: u16 = 0x0908;
    /// Distributed clock (DC) port 3 receive time in ns.
    pub const DcTimePort3: u16 = 0x090c;
    /// DC system receive time.
    pub const DcReceiveTime: u16 = 0x0918;
    /// DC system time, `u64`.
    pub const DcSystemTime: u16 = 0x0910;
    /// DC system time offset, `i64`.
    ///
    /// Time difference between System Time (set by first DC-captable SubDevice) and this
    /// SubDevice's local time.
    ///
    /// NOTE: The spec defines this as a `UINT64`, however negative values are required sometimes
    /// and they work fine in practice, so I'm inclined to say this should actually be an `INT64`.
    pub const DcSystemTimeOffset: u16 = 0x0920;
    /// Transmission delay, `u32`.
    ///
    /// Offset between the reference system time (in ns) and the local system time (in ns).
    pub const DcSystemTimeTransmissionDelay: u16 = 0x0928;

    /// DC control loop parameter, `u16`.
    pub const DcControlLoopParam1: u16 = 0x0930;
    /// DC control loop parameter, `u16`.
    pub const DcControlLoopParam2: u16 = 0x0932;
    /// DC control loop parameter, `u16`.
    pub const DcControlLoopParam3: u16 = 0x0934;

    /// DC system time difference, `u32`.
    pub const DcSystemTimeDifference: u16 = 0x092C;

    /// DC Cyclic Unit Control, `u8`.
    ///
    /// ETG1000.4 Table 61 - Distributed clock DLS-user parameter.
    ///
    /// AKA DCCUC. Documentation is very light, with ETG1000.4 only mentioning this as a "reserved"
    /// field. Wireshark describes this register as "DC Cyclic Unit Control".
    pub const DcCyclicUnitControl: u16 = 0x0980;

    /// ETG1000.6 Table 27 - Distributed Clock sync parameter, `u8`.
    ///
    /// AKA ETG1000.4 Table 61 DC user P1.
    pub const DcSyncActive: u16 = 0x0981;

    /// ETG1000.6 Table 27 - Distributed Clock sync parameter, `u32`.
    ///
    /// AKA ETG1000.4 Table 61 DC user P4.
    pub const DcSyncStartTime: u16 = 0x0990;

    /// ETG1000.6 Table 27 - Distributed Clock sync parameter, `u32`.
    ///
    /// AKA ETG1000.4 Table 61 DC user P6.
    ///
    /// Cycle time is in nanoseconds.
    pub const DcSync0CycleTime: u16 = 0x09A0;

    /// See [`RegisterAddress::DcSync0CycleTime`].
    pub const DcSync1CycleTime: u16 = 0x09A4;
}

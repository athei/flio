use num_derive::FromPrimitive;
use num_traits::FromPrimitive;
#[cfg(test)]
use strum_macros::EnumIter;

impl NTStatus {
    pub fn is_success(self) -> bool {
        if let Severity::Success = self.severity() {
            return true;
        }
        false
    }

    pub fn severity(self) -> Severity {
        let severity = (self as u32) >> 30;
        // wont fail because we only put in 2 bytes
        Severity::from_u32(severity).unwrap()
    }

    pub fn facility(self) -> Option<Facility> {
        let facility = ((self as u32) >> 16) & 0xFFF;
        Facility::from_u32(facility)
    }
}

#[repr(u8)]
#[derive(FromPrimitive, Clone, Copy)]
#[cfg_attr(debug_assertions, derive(Debug))]
pub enum Severity {
    Success = 0x00,
    Informational = 0x01,
    Warning = 0x02,
    Error = 0x03,
}

#[repr(u16)]
#[derive(FromPrimitive, Clone, Copy)]
#[cfg_attr(debug_assertions, derive(Debug))]
pub enum Facility {
    Debugger = 0x001,
    RpcRuntime = 0x002,
    RpcStubs = 0x003,
    IoErrorCode = 0x004,
    NtWin32 = 0x007,
    NtSspi = 0x009,
    TerminalServer = 0x00A,
    MuiErrorCode = 0x00B,
    UsbErrorCode = 0x10,
    HidErrorCode = 0x011,
    ClusterErrorCode = 0x013,
    AcpiErrorCode = 0x014,
    SxsErrorCode = 0x015,
    Transaction = 0x019,
    Commonlog = 0x01A,
    Video = 0x01B,
    FilterManager = 0x01C,
    Monitor = 0x01D,
    GraphicsKernel = 0x01E,
    DriverFrameWork = 0x020,
    FveErrorCode = 0x021,
    FWPErrorCode = 0x022,
    NdisErrorCode = 0x023,
    Hypervisor = 0x035,
    Ipsec = 0x036,
    MaximumValue = 0x037,
}

#[repr(u32)]
#[derive(FromPrimitive, Clone, Copy)]
#[cfg_attr(debug_assertions, derive(Debug))]
#[cfg_attr(test, derive(EnumIter))]
pub enum NTStatus {
    Sucess = 0x0000_0000,
    Pending = 0x0000_0103,
    MoreEntries = 0x0000_0105,
    SomeNotMapped = 0x0000_0107,
    NotifyCleanup = 0x0000_010B,
    NotifyEnumDir = 0x0000_010C,
    BufferOverflow = 0x8000_0005,
    NoMoreFiles = 0x8000_0006,
    NoMoreEas = 0x8000_0012,
    InvalidEaName = 0x8000_0013,
    EaListInconsistent = 0x8000_0014,
    InvalidEaFlag = 0x8000_0015,
    StoppedOnSymlink = 0x8000_002D,
    InvalidParameter = 0xC000_000D,
}

#[cfg(test)]
mod tests {
    use super::*;
    use strum::IntoEnumIterator;

    impl NTStatus {
        fn is_custom(self) -> bool {
            (((self as u32) >> 28) & 0x1) == 1
        }

        fn reserved_field(self) -> u32 {
            ((self as u32) >> 29) & 0x1
        }
    }

    #[test]
    fn no_custom() {
        for status in NTStatus::iter() {
            assert!(!status.is_custom());
        }
    }

    #[test]
    fn all_reserved() {
        for status in NTStatus::iter() {
            assert!(status.reserved_field() == 0);
        }
    }

    #[test]
    fn all_severity_exit() {
        for status in NTStatus::iter() {
            status.facility();
        }
    }
}

use std::ffi::c_int;

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[repr(C)]
#[allow(non_snake_case)]
pub struct PinData {
    pub pinCount: c_int,
    pub pinLimit: c_int,
}

impl PinData {
    pub fn new(pin_count: c_int, pin_limit: c_int) -> Self {
        Self {
            pinCount: pin_count,
            pinLimit: pin_limit,
        }
    }
    pub const SIZE: usize = std::mem::size_of::<PinData>();
}

impl From<PinData> for Vec<u8> {
    fn from(value: PinData) -> Self {
        let mut bytes = Vec::with_capacity(PinData::SIZE);
        bytes.extend_from_slice(&value.pinCount.to_be_bytes());
        bytes.extend_from_slice(&value.pinLimit.to_be_bytes());
        bytes
    }
}

impl From<&[u8]> for PinData {
    fn from(bytes: &[u8]) -> Self {
        let pin_count = c_int::from_be_bytes(bytes[0..4].try_into().unwrap());
        let pin_limit = c_int::from_be_bytes(bytes[4..8].try_into().unwrap());
        Self {
            pinCount: pin_count,
            pinLimit: pin_limit,
        }
    }
}

#[derive(Debug, Clone, Copy, serde::Serialize, serde::Deserialize)]
pub struct AttemptInfo {
    pub used: u32,
    pub limit: u32,
}

impl AttemptInfo {
    pub fn from_pin_data(slot: PinData) -> Self {
        let used = if slot.pinCount < 0 {
            0
        } else {
            slot.pinCount as u32
        };
        let limit = if slot.pinLimit <= 0 {
            0
        } else {
            slot.pinLimit as u32
        };
        Self { used, limit }
    }
    pub fn locked(&self) -> bool {
        self.limit > 0 && self.used >= self.limit
    }
    pub fn prompt_tuple(&self) -> (u32, u32) {
        (self.used, self.limit)
    }
}

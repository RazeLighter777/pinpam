pub const PIN_NV_INDEX_BASE: u32 = 0x0100_0000;
pub const PIN_VERSION_UID_MAX: u32 = 0x007F_FFFF;
pub const PIN_VERSION_NV_INDEX_OFFSET: u32 = PIN_VERSION_UID_MAX + 1;
pub const PIN_VERSION_CURRENT: u8 = 2;
pub const PIN_VERSION_TAG_SIZE: usize = 1;
pub const DEFAULT_PINUTIL_PATH: &str = "/usr/bin/pinutil";

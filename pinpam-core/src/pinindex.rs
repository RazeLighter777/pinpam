use tss_esapi::handles::NvIndexTpmHandle;

use crate::{
    pinconstants::*,
    pinerror::{PinError, PinResult},
};

pub fn nv_index_for_uid(uid: u32) -> PinResult<NvIndexTpmHandle> {
    // add uid to base index, checking for collisions
    let index_value = PIN_NV_INDEX_BASE
        .checked_add_signed(uid as i32)
        .ok_or(PinError::UidOverflow(uid))?;
    NvIndexTpmHandle::new(index_value).map_err(|e| PinError::TpmError(format!("{e}")))
}

pub fn version_nv_index_for_uid(uid: u32) -> PinResult<NvIndexTpmHandle> {
    if uid > PIN_VERSION_UID_MAX {
        return Err(PinError::UidOverflow(uid));
    }

    let index_value = PIN_NV_INDEX_BASE
        .checked_add(PIN_VERSION_NV_INDEX_OFFSET)
        .and_then(|base| base.checked_add(uid))
        .ok_or(PinError::UidOverflow(uid))?;
    NvIndexTpmHandle::new(index_value).map_err(|e| PinError::TpmError(format!("{e}")))
}

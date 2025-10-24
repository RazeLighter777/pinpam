//! Core TPM PIN management primitives.
//!
//! This module exposes a high-level interface for provisioning, removing and
//! validating user PINs that are sealed inside TPM NV storage.

use log::{debug, trace};
use nix::unistd::Uid;
use std::{
    convert::{TryFrom, TryInto},
    ffi::c_int,
    io::Write,
};
use thiserror::Error;
use tss_esapi::{
    abstraction::nv::{self, read_full, NvOpenOptions, NvReaderWriter},
    attributes::{NvIndexAttributesBuilder, SessionAttributesBuilder},
    constants::{response_code::Tss2ResponseCodeKind, tss::TPM2_CC_NV_Write, NvIndexType},
    handles::{AuthHandle, NvIndexHandle, NvIndexTpmHandle, ObjectHandle, SessionHandle},
    interface_types::{
        algorithm::HashingAlgorithm,
        resource_handles::{NvAuth, Provision},
        session_handles::{AuthSession, PolicySession},
    },
    structures::{Auth, Digest, MaxNvBuffer, Nonce, NvPublic, NvPublicBuilder},
    Context, Error as TssError
};

pub type Result<T> = std::result::Result<T, PinError>;

const PIN_NV_INDEX_BASE: u32 = 0x0100_0000;
const PIN_NV_INDEX_MASK: u32 = 0x0000_FFFF;

#[derive(Debug, Error)]
pub enum PinError {
    #[error("PIN is too short (length {0}, minimum {1})")]
    PinTooShort(usize, usize),

    #[error("PIN is too long (length {0}, maximum {1})")]
    PinTooLong(usize, usize),

    #[error("PIN contains invalid characters (only digits are allowed)")]
    PinInvalidCharacter,

    #[error("User '{0}' is already provisioned")]
    AlreadyProvisioned(String),

    #[error("NV index collision for user '{0}'")]
    UidMismatch(String),

    #[error("User '{0}' is not provisioned")]
    NotProvisioned(String),

    #[error("User '{0}' is locked out due to too many failed attempts")]
    LockedOut(String),

    #[error("Corrupted PIN record in TPM NV storage")]
    CorruptedRecord,

    #[error("Permission denied: cannot manage PIN for user '{0}'")]
    PermissionDenied(String),

    #[error("TPM error: {0}")]
    TpmError(#[from] TssError),
}

/// Policy describing acceptable PIN characteristics.
#[derive(Debug, Clone)]
pub struct PinPolicy {
    /// Minimum allowed length (after trimming).
    pub min_length: usize,
    /// Optional maximum length.
    pub max_length: Option<usize>,
    // Maximum allowed failed attempts before lockout.
    pub max_attempts: u32,
    // Duration of lockout.
    pub lockout_duration_secs: u32,
}

impl Default for PinPolicy {
    fn default() -> Self {
        Self {
            min_length: 4,
            max_length: Some(8),
            max_attempts: 3,
            lockout_duration_secs: 600,
        }
    }
}

impl PinPolicy {
    pub fn new(
        min_length: usize,
        max_length: Option<usize>,
        max_attempts: u32,
        lockout_duration_secs: u32,
    ) -> Self {
        Self {
            min_length,
            max_length,
            max_attempts,
            lockout_duration_secs,
        }
    }
    pub fn validate(&self, pin: u32) -> Result<()> {
        let pin_str = pin.to_string();
        let length = pin_str.len();

        if length < self.min_length {
            return Err(PinError::PinTooShort(length, self.min_length));
        }

        if let Some(max_len) = self.max_length {
            if length > max_len {
                return Err(PinError::PinTooLong(length, max_len));
            }
        }

        Ok(())
    }
}

pub struct PinManager {
    context: Context,
    policy: PinPolicy,
}
#[derive(Debug, Clone, PartialEq, Eq)]
#[repr(C)]
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

impl Into<Vec<u8>> for PinData {
    fn into(self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(Self::SIZE);
        bytes.extend_from_slice(&self.pinCount.to_be_bytes());
        bytes.extend_from_slice(&self.pinLimit.to_be_bytes());
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

/// Result of PIN verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerificationResult {
    /// PIN verification succeeded. Contains the current PinData with attempt counters.
    Success(PinData),
    /// PIN verification failed - incorrect PIN provided.
    Invalid,
    /// User is locked out due to too many failed attempts.
    LockedOut,
}

/// Result of authenticated PIN deletion.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeleteResult {
    /// PIN deletion succeeded.
    Success,
    /// PIN deletion failed - incorrect PIN provided.
    Invalid,
    /// User is locked out due to too many failed attempts.
    LockedOut,
}

impl PinManager {
    /// Create a new PinManager with the given policy.
    pub fn new(policy: PinPolicy) -> Result<Self> {
        use std::str::FromStr;
        use tss_esapi::tcti_ldr::TctiNameConf;

        let tcti = TctiNameConf::from_str("device:/dev/tpmrm0")?;
        let context = Context::new(tcti)?;
        Ok(Self { context, policy })
    }

    /// Provision a new PIN for the supplied user, overwriting anything that might exist.
    pub fn setup_pin(&mut self, uid: u32, pin: u32) -> Result<()> {
        debug!("Setting up PIN for user '{}'.", uid);

        self.policy.validate(pin)?;

        let nv_index = nv_index_for_uid(uid)?;

        if let Some(_) = self.read_pin_slot_owner(nv_index)? {
            return Err(PinError::AlreadyProvisioned(uid.to_string()));
        }

        self.define_pin_slot(nv_index, pin)?;

        let slot = PinData::new(0, self.policy.max_attempts as c_int);

        Ok(())
    }

    /// Delete the stored PIN for a user, requiring PIN authentication.
    /// This allows a user to delete their own PIN by providing the correct PIN.
    /// Returns detailed information about the deletion result.
    /// uses delete_pin_admin internally after verifying the pin
    pub fn delete_pin_with_auth(&mut self, uid: u32, pin: u32) -> Result<DeleteResult> {
        match self.verify_pin(uid, pin)? {
            VerificationResult::Success(_) => {
                self.delete_pin_admin(uid)?;
                Ok(DeleteResult::Success)
            }
            VerificationResult::Invalid => Ok(DeleteResult::Invalid),
            VerificationResult::LockedOut => Ok(DeleteResult::LockedOut),
        }
    }

    /// Delete the stored PIN for a user with administrative privileges (no PIN required).
    /// This is intended for use by root or system administrators.
    pub fn delete_pin_admin(&mut self, uid: u32) -> Result<()> {
        debug!("Administratively deleting PIN for user '{}'.", uid);
        let nv_index = nv_index_for_uid(uid)?;
        let _new_nv_index_handle = self
            .context
            .tr_from_tpm_public(nv_index.into())
            .map(NvIndexHandle::from)?;
        self.execute_with_auth_session(|ctx| {
            ctx.nv_undefine_space(Provision::Owner, _new_nv_index_handle)
        })?;
        Ok(())
    }

    /// Validate a user-supplied PIN against the sealed TPM value.
    /// Returns detailed information about the verification result.
    pub fn verify_pin(&mut self, uid: u32, pin: u32) -> Result<VerificationResult> {
        trace!("Verifying PIN for user '{}'.", uid);
        self.policy.validate(pin)?;

        let nv_index = nv_index_for_uid(uid)?;
        let _new_nv_index_handle = self
            .context
            .tr_from_tpm_public(nv_index.into())
            .map(NvIndexHandle::from)?;

        self.context
            .execute_with_nullauth_session(|ctx| {
                let auth = Auth::try_from(pin.to_string().as_bytes())?;
                ctx.tr_set_auth(_new_nv_index_handle.into(), auth)?;

                let ret = ctx.nv_read(
                    NvAuth::NvIndex(_new_nv_index_handle),
                    _new_nv_index_handle,
                    PinData::SIZE as u16,
                    0,
                );
                ret
            })
            .map(|data| {
                let slot = PinData::from(data.as_slice());
                if slot.pinCount >= slot.pinLimit {
                    VerificationResult::LockedOut
                } else {
                    VerificationResult::Success(slot)
                }
            })
            .or_else(|e| match e {
                TssError::Tss2Error(rc) => match rc.kind() {
                    Some(Tss2ResponseCodeKind::AuthFail) | Some(Tss2ResponseCodeKind::BadAuth) => {
                        Ok(VerificationResult::Invalid)
                    }
                    Some(Tss2ResponseCodeKind::Handle)
                    | Some(Tss2ResponseCodeKind::NvUninitialized) => {
                        Err(PinError::NotProvisioned(uid.to_string()))
                    }
                    _ => Err(PinError::TpmError(TssError::Tss2Error(rc))),
                },
                _ => Err(PinError::TpmError(e)),
            })
    }
    pub fn clear_sessions(&mut self) -> Result<()> {
        self.context.clear_sessions();
        Ok(())
    }
    /// Report whether a user is currently locked out.
    pub fn is_locked_out(&mut self, uid: u32) -> Result<bool> {
        let nv_index = nv_index_for_uid(uid)?;
        match self.read_pin_slot_owner(nv_index)? {
            Some(slot) => {
                if slot.pinCount >= slot.pinLimit {
                    Ok(true)
                } else {
                    Ok(false)
                }
            }
            None => Ok(false),
        }
    }

    /// Return the failed-attempt counter for a user.
    pub fn get_attempt_count(&mut self, uid: u32) -> Result<Option<u32>> {
        let nv_index = nv_index_for_uid(uid)?;
        match self.read_pin_slot_owner(nv_index)? {
            Some(slot) => Ok(Some(slot.pinCount as u32)),
            None => Ok(None),
        }
    }

    /// Helper method to execute operations within an authenticated HMAC session.
    /// This ensures proper session management for TPM operations that require authentication.
    fn execute_with_auth_session<F, T>(&mut self, f: F) -> Result<T>
    where
        F: FnOnce(&mut Context) -> std::result::Result<T, TssError>,
    {
        let session = self.context.start_auth_session(
            None,
            None,
            None,
            tss_esapi::constants::SessionType::Hmac,
            tss_esapi::structures::SymmetricDefinition::AES_256_CFB,
            HashingAlgorithm::Sha256,
        )?;

        let ret = self
            .context
            .execute_with_session(session, f)
            .map_err(PinError::from);
        self.clear_sessions()?;
        ret
    }

    fn define_pin_slot(&mut self, nv_index: NvIndexTpmHandle, pin: u32) -> Result<()> {
        // Step 2: Apply policy_nv_written to the trial session
        // This sets up the policy that the NV index must be in the "written" state
        let auth_value = Auth::try_from(pin.to_string().as_bytes())?;
        let (nv_public, digest) = self.context.execute_without_session(|mut ctx| {
            // Step 1: Create a trial policy session to compute the policy digest
            let trial_session = ctx
                .start_auth_session(
                    None,
                    None,
                    None,
                    tss_esapi::constants::SessionType::Trial,
                    tss_esapi::structures::SymmetricDefinition::AES_256_CFB,
                    HashingAlgorithm::Sha256,
                )?
                .expect("Failed to create trial session");
            let (policy_auth_session_attributes, policy_auth_session_attributes_mask) =
                SessionAttributesBuilder::new()
                    .with_decrypt(true)
                    .with_encrypt(true)
                    .build();//
            ctx.tr_sess_set_attributes(
                trial_session,
                policy_auth_session_attributes,
                policy_auth_session_attributes_mask,
            )?;

            let (policy_auth_session_attributes, policy_auth_session_attributes_mask) =
                SessionAttributesBuilder::new()
                    .with_decrypt(true)
                    .with_encrypt(true)
                    .build();//
            let policy_session = PolicySession::try_from(trial_session)?;
            ctx.tr_sess_set_attributes(
                tss_esapi::interface_types::session_handles::AuthSession::PolicySession(policy_session),
                policy_auth_session_attributes,
                policy_auth_session_attributes_mask,
            )?;
            ctx.policy_command_code(
                policy_session,
                tss_esapi::constants::CommandCode::NvWrite,
            )?;
            ctx.policy_nv_written(policy_session, false)?;
            let digest = ctx.policy_get_digest(policy_session)?;
            let attributes = NvIndexAttributesBuilder::new()
                .with_nv_index_type(NvIndexType::PinFail)
                .with_auth_read(true)
                .with_owner_read(true)
                .with_policy_write(true)
                .with_no_da(true)
                .build()?;
            attributes.validate()?;
            let nv_public = NvPublic::builder()
                .with_nv_index(nv_index)
                .with_index_name_algorithm(HashingAlgorithm::Sha256)
                .with_index_attributes(attributes)
                .with_data_area_size(PinData::SIZE)
                .with_index_auth_policy(digest.clone())
                .build()?;
            ctx.clear_sessions();
            ctx.flush_context(SessionHandle::from(trial_session).into())?;
            Ok::<(NvPublic, tss_esapi::structures::Digest), TssError>((nv_public,digest))
        })?;
        self.context.execute_with_nullauth_session(|ctx| {
            let handle = ctx.nv_define_space(
                Provision::Owner,
                Some(auth_value.clone()),
                nv_public,
            )?;
            Ok::<(), TssError>(())
        })?;

        self.context.execute_without_session(|ctx| {
            let auth_session = ctx.start_auth_session(
                None,
                None,
                None,
                tss_esapi::constants::SessionType::Policy,
                tss_esapi::structures::SymmetricDefinition::AES_256_CFB,
                HashingAlgorithm::Sha256,
            )?.expect("Failed to create auth session");
            // re-apply the same policy to the auth session
            let (policy_auth_session_attributes, policy_auth_session_attributes_mask) =
                SessionAttributesBuilder::new()
                    .with_decrypt(true)
                    .with_encrypt(true)
                    .build();//
            ctx.tr_sess_set_attributes(
                auth_session,
                policy_auth_session_attributes,
                policy_auth_session_attributes_mask,
            )?;
            let policy_session = PolicySession::try_from(auth_session)?;
            ctx.tr_sess_set_attributes(
                tss_esapi::interface_types::session_handles::AuthSession::PolicySession(policy_session),
                policy_auth_session_attributes,
                policy_auth_session_attributes_mask,
            )?;
            ctx.policy_command_code(
                policy_session,
                tss_esapi::constants::CommandCode::NvWrite,
            )?;
            ctx.policy_nv_written(policy_session, false)?;

            let nv_index_handle = ctx
                .tr_from_tpm_public(nv_index.into())
                .map(NvIndexHandle::from)?;
            ctx.execute_with_session(Some(auth_session), |ctx| {
                ctx.tr_set_auth(SessionHandle::from(auth_session).into(), auth_value)?;
                let initial_data = PinData::new(0, self.policy.max_attempts as c_int);
                let initial_bytes: Vec<u8> = initial_data.into();
                ctx.nv_write(
                    NvAuth::NvIndex(nv_index_handle),
                    nv_index_handle,
                    MaxNvBuffer::try_from(initial_bytes.as_slice()).unwrap(),
                    0,
                )?;
                Ok(())
             })?;
            Ok::<(), TssError>(())
        })?;

        Ok(())
    }

    fn read_pin_slot_owner(&mut self, nv_index: NvIndexTpmHandle) -> Result<Option<PinData>> {
        let result = self.execute_with_auth_session(|ctx| {
            let data = read_full(ctx, NvAuth::Owner, nv_index)?;
            let slot = PinData::from(data.as_slice());
            Ok(slot)
        });

        // Handle the case where the NV index doesn't exist
        match result {
            Ok(slot) => Ok(Some(slot)),
            Err(PinError::TpmError(TssError::Tss2Error(rc))) => match rc.kind() {
                Some(Tss2ResponseCodeKind::Handle)
                | Some(Tss2ResponseCodeKind::NvUninitialized) => Ok(None),
                _ => Err(PinError::TpmError(TssError::Tss2Error(rc))),
            },
            Err(e) => Err(e),
        }
    }
}

fn nv_index_for_uid(uid: u32) -> Result<NvIndexTpmHandle> {
    // add uid to base index, checking for collisions
    let index_value = PIN_NV_INDEX_BASE + uid;
    NvIndexTpmHandle::new(index_value).map_err(PinError::from)
}

pub fn get_uid() -> u32 {
    Uid::current().as_raw()
}

/// Check if the current user can manage the target user's PIN.
/// Root (uid 0) can manage anyone's PIN, users can only manage their own.
pub fn can_manage_pin(target_uid: u32) -> bool {
    let current_uid = get_uid();
    current_uid == 0 || current_uid == target_uid
}

/// Get UID from username using nix crate.
pub fn get_uid_from_username(username: &str) -> Option<u32> {
    use nix::unistd::User;
    User::from_name(username).ok()?.map(|u| u.uid.as_raw())
}

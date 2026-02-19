use std::ffi::c_int;
use std::str::FromStr;

use tss_esapi::abstraction::nv::read_full;
use tss_esapi::attributes::{NvIndexAttributesBuilder, SessionAttributesBuilder};
use tss_esapi::constants::{NvIndexType, Tss2ResponseCodeKind};
use tss_esapi::handles::{NvIndexHandle, NvIndexTpmHandle, SessionHandle};
use tss_esapi::interface_types::algorithm::HashingAlgorithm;
use tss_esapi::interface_types::resource_handles::{NvAuth, Provision};
use tss_esapi::interface_types::session_handles::PolicySession;
use tss_esapi::structures::{Auth, MaxNvBuffer, NvPublic};
use tss_esapi::tcti_ldr::DeviceConfig;
use tss_esapi::Context;

use crate::pinconstants::*;
use crate::pindata::PinData;
use crate::pinerror::{DeleteResult, TssError, VerificationResult};
use crate::pinindex::version_nv_index_for_uid;
use crate::util::normalize_legacy_pin;
use crate::{
    pinerror::{PinError, PinResult},
    pinindex::nv_index_for_uid,
    pinpolicy,
};
use log::{debug, trace, warn};
pub struct PinManager {
    context: Context,
    policy: pinpolicy::PinPolicy,
}

impl PinManager {
    /// Create a new PinManager with the given policy.
    pub fn new(policy: pinpolicy::PinPolicy) -> PinResult<Self> {
        use std::str::FromStr;
        use tss_esapi::tcti_ldr::TctiNameConf;

        let tcti = TctiNameConf::from_str("device:/dev/tpmrm0")?;
        let context = Context::new(tcti)?;
        Ok(Self { context, policy })
    }

    /// Provision a new PIN for the supplied user, overwriting anything that might exist.
    pub fn setup_pin(&mut self, uid: u32, pin: String) -> PinResult<()> {
        debug!("Setting up PIN for user '{}'.", uid);

        self.policy.validate(&pin)?;

        let nv_index = nv_index_for_uid(uid)?;

        if self.read_pin_slot_owner(nv_index)?.is_some() {
            return Err(PinError::AlreadyProvisioned(uid));
        }

        self.define_pin_slot(nv_index, &pin)?;
        self.restart_context()?;
        if let Err(err) = self.write_pin_version_tag(uid, PIN_VERSION_CURRENT) {
            warn!(
                "Failed to write PIN version tag for user '{}': {}",
                uid, err
            );
            self.restart_context()?;
            match self.delete_pin_admin(uid) {
                Ok(()) => {
                    return Err(PinError::TpmError(format!(
                        "failed to write PIN version tag: {}",
                        err
                    )));
                }
                Err(cleanup_err) => {
                    return Err(PinError::TpmError(format!(
                        "failed to write PIN version tag ({}) and failed to rollback PIN setup ({})",
                        err, cleanup_err
                    )));
                }
            }
        }

        Ok(())
    }

    /// Delete the stored PIN for a user, requiring PIN authentication.
    /// This allows a user to delete their own PIN by providing the correct PIN.
    /// Returns detailed information about the deletion PinResult.
    /// uses delete_pin_admin internally after verifying the pin
    pub fn delete_pin_with_auth(&mut self, uid: u32, pin: &str) -> PinResult<DeleteResult> {
        match self.verify_pin(uid, pin)? {
            VerificationResult::Success(_) => {
                self.delete_pin_admin(uid)?;
                Ok(DeleteResult::Success)
            }
            VerificationResult::Invalid { locked } => Ok(DeleteResult::Invalid { locked }),
            VerificationResult::LockedOut => Ok(DeleteResult::LockedOut),
        }
    }

    /// Delete the stored PIN for a user with administrative privileges (no PIN required).
    /// This is intended for use by root or system administrators.
    pub fn delete_pin_admin(&mut self, uid: u32) -> PinResult<()> {
        debug!("Administratively deleting PIN for user '{}'.", uid);
        let nv_index = nv_index_for_uid(uid)?;
        let session = self.context.start_auth_session(
            None,
            None,
            None,
            tss_esapi::constants::SessionType::Hmac,
            tss_esapi::structures::SymmetricDefinition::AES_256_CFB,
            HashingAlgorithm::Sha256,
        )?;
        let result = self.context.execute_with_session(session, |ctx| {
            let nv_index_handle = ctx
                .tr_from_tpm_public(nv_index.into())
                .map(NvIndexHandle::from)?;
            ctx.nv_undefine_space(Provision::Owner, nv_index_handle)?;
            Ok::<(), TssError>(())
        });
        self.clear_sessions();

        match result {
            Ok(()) => {}
            Err(TssError::Tss2Error(rc)) => match rc.kind() {
                Some(Tss2ResponseCodeKind::Handle)
                | Some(Tss2ResponseCodeKind::NvUninitialized) => {
                    return Err(PinError::NotProvisioned(uid));
                }
                _ => return Err(PinError::from(TssError::Tss2Error(rc))),
            },
            Err(e) => return Err(PinError::from(e)),
        }

        if let Err(err) = self.delete_pin_version_tag(uid) {
            warn!(
                "Failed to delete PIN version tag for user '{}': {}",
                uid, err
            );
        }
        Ok(())
    }

    /// Validate a user-supplied PIN against the sealed TPM value.
    /// Returns detailed information about the verification PinResult.
    pub fn verify_pin(&mut self, uid: u32, pin: &str) -> PinResult<VerificationResult> {
        trace!("Verifying PIN for user '{}'.", uid);
        self.policy.validate(pin)?;

        self.clear_sessions();
        match self.read_pin_version_tag(uid)? {
            Some(version) => {
                if version != PIN_VERSION_CURRENT {
                    return Err(PinError::TpmError(format!(
                        "unsupported PIN version tag: {}",
                        version
                    )));
                }
                self.verify_pin_exact(uid, pin)
            }
            None => {
                let legacy_pin = normalize_legacy_pin(pin);
                let pin_result = self.verify_pin_exact(uid, &legacy_pin)?;
                if matches!(pin_result, VerificationResult::Success(_)) {
                    self.restart_context()?;
                    if let Err(err) = self.migrate_legacy_pin_format(uid, pin) {
                        warn!(
                            "Failed to migrate legacy PIN format for user '{}': {}",
                            uid, err
                        );
                    }
                    self.restart_context()?;
                }
                Ok(pin_result)
            }
        }
    }

    fn verify_pin_exact(&mut self, uid: u32, pin: &str) -> PinResult<VerificationResult> {
        let nv_index = nv_index_for_uid(uid)?;
        let _new_nv_index_handle = self
            .context
            .tr_from_tpm_public(nv_index.into())
            .map(NvIndexHandle::from)?;

        self.context
            .execute_with_nullauth_session(|ctx| {
                let auth = Auth::try_from(pin.to_string().as_bytes())?;
                ctx.tr_set_auth(_new_nv_index_handle.into(), auth)?;

                ctx.nv_read(
                    NvAuth::NvIndex(_new_nv_index_handle),
                    _new_nv_index_handle,
                    PinData::SIZE as u16,
                    0,
                )
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
                        let locked = self
                            .read_pin_slot_owner(nv_index)
                            .is_ok_and(|opt_pin_data| {
                                opt_pin_data.is_some_and(|slot| slot.pinCount >= slot.pinLimit)
                            });
                        Ok(VerificationResult::Invalid { locked })
                    }
                    Some(Tss2ResponseCodeKind::Handle)
                    | Some(Tss2ResponseCodeKind::NvUninitialized) => {
                        Err(PinError::NotProvisioned(uid))
                    }
                    _ => Err(PinError::from(TssError::Tss2Error(rc))),
                },
                _ => Err(PinError::from(e)),
            })
    }

    fn migrate_legacy_pin_format(&mut self, uid: u32, entered_pin: &str) -> PinResult<()> {
        let legacy_pin = normalize_legacy_pin(entered_pin);

        if legacy_pin == entered_pin {
            return self.write_pin_version_tag(uid, PIN_VERSION_CURRENT);
        }

        self.delete_pin_admin(uid)?;
        self.restart_context()?;
        self.setup_pin(uid, entered_pin.to_owned())?;
        self.restart_context()?;
        Ok(())
    }

    fn read_pin_version_tag(&mut self, uid: u32) -> PinResult<Option<u8>> {
        let nv_index = version_nv_index_for_uid(uid)?;
        let pin_result = self
            .context
            .execute_with_nullauth_session(|ctx| read_full(ctx, NvAuth::Owner, nv_index));
        self.clear_sessions();

        match pin_result {
            Ok(data) => {
                if data.len() != PIN_VERSION_TAG_SIZE {
                    return Err(PinError::TpmError(format!(
                        "invalid PIN version tag payload size: {}",
                        data.len()
                    )));
                }
                Ok(data.first().copied())
            }
            Err(TssError::Tss2Error(rc)) => match rc.kind() {
                Some(Tss2ResponseCodeKind::Handle)
                | Some(Tss2ResponseCodeKind::NvUninitialized) => Ok(None),
                _ => Err(PinError::from(TssError::Tss2Error(rc))),
            },
            Err(e) => Err(PinError::from(e)),
        }
    }

    fn write_pin_version_tag(&mut self, uid: u32, version: u8) -> PinResult<()> {
        let nv_index = version_nv_index_for_uid(uid)?;

        match self.write_pin_version_tag_existing(nv_index, version) {
            Ok(()) => Ok(()),
            Err(e) => match e {
                PinError::TpmError(_) => {
                    // Try to extract TssError details if it's a TpmError
                    self.define_pin_version_tag(nv_index)?;
                    self.write_pin_version_tag_existing(nv_index, version)
                }
                _ => Err(e),
            },
        }
    }

    fn write_pin_version_tag_existing(
        &mut self,
        nv_index: NvIndexTpmHandle,
        version: u8,
    ) -> PinResult<()> {
        let payload = [version];
        let pin_result = self.context.execute_with_nullauth_session(|ctx| {
            let handle = ctx
                .tr_from_tpm_public(nv_index.into())
                .map(NvIndexHandle::from)?;
            ctx.nv_write(
                NvAuth::Owner,
                handle,
                MaxNvBuffer::try_from(payload.as_slice())?,
                0,
            )
        });
        self.clear_sessions();
        pin_result.map_err(PinError::from)
    }

    fn define_pin_version_tag(&mut self, nv_index: NvIndexTpmHandle) -> PinResult<()> {
        self.context.execute_with_nullauth_session(|ctx| {
            let attributes = NvIndexAttributesBuilder::new()
                .with_nv_index_type(NvIndexType::Ordinary)
                .with_owner_read(true)
                .with_owner_write(true)
                .with_no_da(true)
                .build()?;
            attributes.validate()?;

            let nv_public = NvPublic::builder()
                .with_nv_index(nv_index)
                .with_index_name_algorithm(HashingAlgorithm::Sha256)
                .with_index_attributes(attributes)
                .with_data_area_size(PIN_VERSION_TAG_SIZE)
                .build()?;

            ctx.nv_define_space(Provision::Owner, None, nv_public)?;
            Ok::<(), TssError>(())
        })?;
        self.clear_sessions();
        Ok(())
    }

    fn delete_pin_version_tag(&mut self, uid: u32) -> PinResult<()> {
        let nv_index = version_nv_index_for_uid(uid)?;
        let pin_result = self.context.execute_with_nullauth_session(|ctx| {
            let handle = ctx
                .tr_from_tpm_public(nv_index.into())
                .map(NvIndexHandle::from)?;
            ctx.nv_undefine_space(Provision::Owner, handle)
        });
        self.clear_sessions();

        match pin_result {
            Ok(()) => Ok(()),
            Err(TssError::Tss2Error(rc)) => match rc.kind() {
                Some(Tss2ResponseCodeKind::Handle)
                | Some(Tss2ResponseCodeKind::NvUninitialized) => Ok(()),
                _ => Err(PinError::from(TssError::Tss2Error(rc))),
            },
            Err(e) => Err(PinError::from(e)),
        }
    }
    pub fn clear_sessions(&mut self) {
        self.context.clear_sessions();
    }
    pub fn restart_context(&mut self) -> PinResult<()> {
        self.context = Context::new(tss_esapi::tcti_ldr::TctiNameConf::Device(
            DeviceConfig::from_str("/dev/tpmrm0").map_err(PinError::from)?,
        ))
        .map_err(PinError::from)?;
        Ok(())
    }
    /// Report whether a user is currently locked out.
    pub fn is_locked_out(&mut self, uid: u32) -> PinResult<bool> {
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
    pub fn get_attempt_count(&mut self, uid: u32) -> PinResult<Option<u32>> {
        let nv_index = nv_index_for_uid(uid)?;
        match self.read_pin_slot_owner(nv_index)? {
            Some(slot) => Ok(Some(slot.pinCount as u32)),
            None => Ok(None),
        }
    }

    /// Return the full PIN slot data for a user if provisioned.
    pub fn get_pin_slot(&mut self, uid: u32) -> PinResult<Option<PinData>> {
        let nv_index = nv_index_for_uid(uid)?;
        self.read_pin_slot_owner(nv_index)
    }
    fn define_pin_slot(&mut self, nv_index: NvIndexTpmHandle, pin: &str) -> PinResult<()> {
        // Step 2: Apply policy_nv_written to the trial session
        // This sets up the policy that the NV index must be in the "written" state
        let auth_value = Auth::try_from(pin.to_string().as_bytes())?;
        let (nv_public, _) = self.context.execute_without_session(|ctx| {
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
                    .build(); //
            ctx.tr_sess_set_attributes(
                trial_session,
                policy_auth_session_attributes,
                policy_auth_session_attributes_mask,
            )?;

            let (policy_auth_session_attributes, policy_auth_session_attributes_mask) =
                SessionAttributesBuilder::new()
                    .with_decrypt(true)
                    .with_encrypt(true)
                    .build(); //
            let policy_session = PolicySession::try_from(trial_session)?;
            ctx.tr_sess_set_attributes(
                tss_esapi::interface_types::session_handles::AuthSession::PolicySession(
                    policy_session,
                ),
                policy_auth_session_attributes,
                policy_auth_session_attributes_mask,
            )?;
            ctx.policy_command_code(policy_session, tss_esapi::constants::CommandCode::NvWrite)?;
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
            Ok::<(NvPublic, tss_esapi::structures::Digest), TssError>((nv_public, digest))
        })?;
        self.context.execute_with_nullauth_session(|ctx| {
            ctx.nv_define_space(Provision::Owner, Some(auth_value.clone()), nv_public)?;
            Ok::<(), TssError>(())
        })?;

        self.context.execute_without_session(|ctx| {
            let auth_session = ctx
                .start_auth_session(
                    None,
                    None,
                    None,
                    tss_esapi::constants::SessionType::Policy,
                    tss_esapi::structures::SymmetricDefinition::AES_256_CFB,
                    HashingAlgorithm::Sha256,
                )?
                .expect("Failed to create auth session");
            // re-apply the same policy to the auth session
            let (policy_auth_session_attributes, policy_auth_session_attributes_mask) =
                SessionAttributesBuilder::new()
                    .with_decrypt(true)
                    .with_encrypt(true)
                    .build(); //
            ctx.tr_sess_set_attributes(
                auth_session,
                policy_auth_session_attributes,
                policy_auth_session_attributes_mask,
            )?;
            let policy_session = PolicySession::try_from(auth_session)?;
            ctx.tr_sess_set_attributes(
                tss_esapi::interface_types::session_handles::AuthSession::PolicySession(
                    policy_session,
                ),
                policy_auth_session_attributes,
                policy_auth_session_attributes_mask,
            )?;
            ctx.policy_command_code(policy_session, tss_esapi::constants::CommandCode::NvWrite)?;
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

    fn read_pin_slot_owner(&mut self, nv_index: NvIndexTpmHandle) -> PinResult<Option<PinData>> {
        let session = self.context.start_auth_session(
            None,
            None,
            None,
            tss_esapi::constants::SessionType::Hmac,
            tss_esapi::structures::SymmetricDefinition::AES_256_CFB,
            HashingAlgorithm::Sha256,
        )?;

        let result = self.context.execute_with_session(session, |ctx| {
            let data = read_full(ctx, NvAuth::Owner, nv_index)?;
            Ok(PinData::from(data.as_slice()))
        });
        self.clear_sessions();

        match result {
            Ok(slot) => Ok(Some(slot)),
            Err(TssError::Tss2Error(rc)) => match rc.kind() {
                Some(Tss2ResponseCodeKind::Handle)
                | Some(Tss2ResponseCodeKind::NvUninitialized) => Ok(None),
                _ => Err(PinError::from(TssError::Tss2Error(rc))),
            },
            Err(e) => Err(PinError::from(e)),
        }
    }
}

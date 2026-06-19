//! End-to-end integration tests for the PIN lifecycle, running against an
//! `swtpm` simulator.
//!
//! The emphasis here is on backward compatibility: once a PIN has been
//! provisioned by any version of pinpam, the current code must remain able to
//! verify it. New tests should be additive — never tighten an existing
//! invariant in a way that would invalidate state produced by a released
//! version.

mod common;

use std::path::PathBuf;

use pinpam_core::pin::Pin;
use pinpam_core::pinerror::VerificationResult;
use pinpam_core::pinmanager::PinManager;
use pinpam_core::pinpolicy::PinPolicy;

const TEST_UID: u32 = 4242;
const PIN_STRING: &str = "1234";
const WRONG_PIN: &str = "9999";

fn test_policy(max_attempts: u32) -> PinPolicy {
    PinPolicy {
        min_length: 4,
        max_length: Some(8),
        allow_alphanumeric: false,
        max_attempts,
        pinutil_path: PathBuf::from("/usr/bin/true"),
        tcti: None,
    }
}

fn pin(s: &str) -> Pin {
    Pin::new(s, &test_policy(5)).expect("valid PIN")
}

fn manager(swtpm: &common::Swtpm, max_attempts: u32) -> PinManager {
    PinManager::with_tcti(test_policy(max_attempts), swtpm.tcti_spec())
        .expect("connect to swtpm")
}

#[test]
fn pin_lifecycle_create_verify_delete() {
    let Some(swtpm) = common::try_start_swtpm() else { return };
    let mut mgr = manager(&swtpm, 5);

    mgr.setup_pin(TEST_UID, &pin(PIN_STRING)).expect("setup");
    mgr.restart_context().expect("restart after setup");

    match mgr.verify_pin(TEST_UID, &pin(PIN_STRING)).expect("verify") {
        VerificationResult::Success(slot) => {
            assert_eq!(slot.pinLimit, 5);
        }
        other => panic!("expected Success, got {other:?}"),
    }
    mgr.restart_context().expect("restart after verify");

    mgr.delete_pin_admin(TEST_UID).expect("delete");
    assert!(mgr.get_pin_slot(TEST_UID).expect("read slot").is_none());
}

#[test]
fn wrong_pin_locks_out_after_max_attempts() {
    let Some(swtpm) = common::try_start_swtpm() else { return };
    let mut mgr = manager(&swtpm, 3);

    mgr.setup_pin(TEST_UID, &pin(PIN_STRING)).expect("setup");
    mgr.restart_context().expect("restart after setup");

    for attempt in 1..=2 {
        match mgr.verify_pin(TEST_UID, &pin(WRONG_PIN)).expect("verify") {
            VerificationResult::Invalid { locked } => {
                assert!(!locked, "should not be locked yet on attempt {attempt}");
            }
            other => panic!("expected Invalid, got {other:?}"),
        }
        mgr.restart_context().expect("restart between wrong attempts");
    }

    // Third wrong attempt trips the lockout.
    match mgr.verify_pin(TEST_UID, &pin(WRONG_PIN)).expect("verify") {
        VerificationResult::Invalid { locked: true } => {}
        other => panic!("expected Invalid {{ locked: true }}, got {other:?}"),
    }
    mgr.restart_context().expect("restart after lockout");

    // The slot now reports locked, regardless of which auth-related error the
    // TPM returns on a subsequent verify (real TPMs and swtpm differ here).
    assert!(mgr.is_locked_out(TEST_UID).expect("is_locked_out"));
}

#[test]
fn pin_survives_pinmanager_drop_and_recreate() {
    let Some(swtpm) = common::try_start_swtpm() else { return };

    {
        let mut mgr = manager(&swtpm, 5);
        mgr.setup_pin(TEST_UID, &pin(PIN_STRING)).expect("setup");
    }

    let mut mgr = manager(&swtpm, 5);
    let result = mgr.verify_pin(TEST_UID, &pin(PIN_STRING)).expect("verify");
    assert!(
        matches!(result, VerificationResult::Success(_)),
        "expected Success after PinManager recreate, got {result:?}",
    );
}

/// Core backward-compatibility guarantee: a PIN created in one swtpm run must
/// continue to verify after the simulator is fully stopped and restarted from
/// the same persistent state directory. This proves we do not rely on any
/// transient TPM state to authenticate.
#[test]
fn pin_survives_swtpm_restart() {
    let Some(swtpm) = common::try_start_swtpm() else { return };

    {
        let mut mgr = manager(&swtpm, 5);
        mgr.setup_pin(TEST_UID, &pin(PIN_STRING)).expect("setup");
    }

    let state = swtpm.into_persisted_state();
    let Some(swtpm) = common::try_resume_swtpm(state) else { return };

    let mut mgr = manager(&swtpm, 5);
    let result = mgr.verify_pin(TEST_UID, &pin(PIN_STRING)).expect("verify");
    assert!(
        matches!(result, VerificationResult::Success(_)),
        "expected Success after swtpm restart, got {result:?}",
    );
}

/// Simulates a PIN provisioned by v0.0.3 (no version tag NV index) and
/// confirms verify_pin still succeeds via the legacy migration path. This
/// guards the "once created, never breaks" promise across the v0.0.3 -> v0.0.4
/// upgrade.
#[test]
fn legacy_pin_without_version_tag_still_verifies() {
    let Some(swtpm) = common::try_start_swtpm() else { return };
    let mut mgr = manager(&swtpm, 5);

    mgr.setup_pin(TEST_UID, &pin(PIN_STRING)).expect("setup");
    mgr.__test_remove_version_tag(TEST_UID)
        .expect("drop version tag to simulate legacy state");
    mgr.restart_context().expect("restart context");

    let result = mgr.verify_pin(TEST_UID, &pin(PIN_STRING)).expect("verify");
    assert!(
        matches!(result, VerificationResult::Success(_)),
        "expected Success on legacy slot, got {result:?}",
    );

    // After migration the tag is back, so a follow-up verify still works.
    let result = mgr.verify_pin(TEST_UID, &pin(PIN_STRING)).expect("verify");
    assert!(
        matches!(result, VerificationResult::Success(_)),
        "expected Success after migration, got {result:?}",
    );
}

/// Two users do not interfere with each other's slots.
#[test]
fn separate_uids_are_independent() {
    let Some(swtpm) = common::try_start_swtpm() else { return };
    let mut mgr = manager(&swtpm, 5);

    let uid_a = 1001;
    let uid_b = 1002;

    mgr.setup_pin(uid_a, &pin("1111")).expect("setup a");
    mgr.restart_context().expect("restart");
    mgr.setup_pin(uid_b, &pin("2222")).expect("setup b");
    mgr.restart_context().expect("restart");

    assert!(matches!(
        mgr.verify_pin(uid_a, &pin("1111")).expect("verify a"),
        VerificationResult::Success(_)
    ));
    mgr.restart_context().expect("restart");
    assert!(matches!(
        mgr.verify_pin(uid_b, &pin("2222")).expect("verify b"),
        VerificationResult::Success(_)
    ));
    mgr.restart_context().expect("restart");

    // Cross-PINs fail.
    assert!(matches!(
        mgr.verify_pin(uid_a, &pin("2222")).expect("cross a"),
        VerificationResult::Invalid { .. }
    ));
}

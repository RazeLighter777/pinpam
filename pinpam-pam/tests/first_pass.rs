//! Integration tests for the `try_first_pass` / `use_first_pass` PAM module
//! arguments.
//!
//! These exercise the parsing and decision logic through the same public API
//! that `pam_sm_authenticate` itself goes through, so they catch regressions
//! in the contract between argument parsing and the decision step.

use std::path::PathBuf;

use pinpam::{ModuleArgs, decide_first_pass};
use pinpam_core::pinpolicy::PinPolicy;

fn policy() -> PinPolicy {
    PinPolicy {
        min_length: 4,
        max_length: Some(8),
        allow_alphanumeric: false,
        max_attempts: 5,
        pinutil_path: PathBuf::from("/usr/bin/true"),
        tcti: None,
    }
}

/// Simulate the typical `pam.d` line `auth sufficient libpinpam.so try_first_pass`
/// and confirm the parsed args drive the correct decision against a valid PIN.
#[test]
fn pam_line_try_first_pass_accepts_valid_pin_from_stack() {
    let args = ModuleArgs::from_strs(["try_first_pass"].into_iter());
    assert!(args.try_first_pass);
    assert!(!args.use_first_pass);

    let policy = policy();
    let decision = decide_first_pass(args, Some("4242"), &policy);
    let pin = decision
        .pin()
        .expect("a valid PIN should be forwarded for verification");
    assert_eq!(pin.as_str(), "4242");
}

/// `try_first_pass` with a stacked password that is *not* a PIN (e.g. the user
/// has a normal unix password) must fall through to a user prompt without
/// touching the TPM.
#[test]
fn pam_line_try_first_pass_falls_through_for_non_pin_token() {
    let args = ModuleArgs::from_strs(["try_first_pass"].into_iter());
    let policy = policy();

    for non_pin in ["sup3rs3cret", "abc", "", "1234a"] {
        let decision = decide_first_pass(args, Some(non_pin), &policy);
        assert!(
            decision.is_prompt_user(),
            "expected prompt fall-through for {non_pin:?}",
        );
    }
}

/// `use_first_pass` must never prompt: any token that isn't a valid PIN is a
/// straight deny. Critically, this includes the very common case where the
/// stack carried a unix password rather than a PIN.
#[test]
fn pam_line_use_first_pass_denies_non_pin_token_without_prompt() {
    let args = ModuleArgs::from_strs(["use_first_pass"].into_iter());
    assert!(args.use_first_pass);
    assert!(!args.try_first_pass);

    let policy = policy();

    for non_pin in ["sup3rs3cret", "", "1234a", "12"] {
        let decision = decide_first_pass(args, Some(non_pin), &policy);
        assert!(
            decision.is_deny(),
            "expected deny for {non_pin:?} under use_first_pass",
        );
    }

    // No authtok cached at all is also a deny.
    assert!(decide_first_pass(args, None, &policy).is_deny());
}

/// `use_first_pass` with a valid PIN should hand it off to the TPM verifier.
#[test]
fn pam_line_use_first_pass_forwards_valid_pin() {
    let args = ModuleArgs::from_strs(["use_first_pass"].into_iter());
    let policy = policy();
    let decision = decide_first_pass(args, Some("12345"), &policy);
    let pin = decision.pin().expect("valid PIN must be forwarded");
    assert_eq!(pin.as_str(), "12345");
}

/// When both flags are set (which some admins do defensively), the stricter
/// `use_first_pass` semantics dominate on the failure path. A valid PIN is
/// still forwarded; a bad token is denied rather than prompted for.
#[test]
fn pam_line_with_both_flags_uses_strictest_failure_mode() {
    let args = ModuleArgs::from_strs(["try_first_pass", "use_first_pass"].into_iter());
    let policy = policy();

    assert!(decide_first_pass(args, Some("4321"), &policy).is_try_first_pass());
    assert!(decide_first_pass(args, Some("not-a-pin"), &policy).is_deny());
    assert!(decide_first_pass(args, None, &policy).is_deny());
}

/// Without either flag, the module ignores any cached authtok and always
/// prompts — this is the historical pinpam behaviour and must not regress.
#[test]
fn pam_line_without_flags_ignores_authtok() {
    let args = ModuleArgs::default();
    let policy = policy();

    assert!(decide_first_pass(args, Some("4242"), &policy).is_prompt_user());
    assert!(decide_first_pass(args, Some("hunter2"), &policy).is_prompt_user());
    assert!(decide_first_pass(args, None, &policy).is_prompt_user());
}

/// PIN-policy bounds (min/max length) are part of the "is this a valid PIN?"
/// gate. A token that would parse as digits but breaches the policy must not
/// be passed to the TPM under `try_first_pass`; doing so would burn one of
/// the user's limited attempts on something the policy already rejects.
#[test]
fn first_pass_honours_policy_length_bounds() {
    let strict = PinPolicy {
        min_length: 6,
        max_length: Some(6),
        ..policy()
    };
    let args = ModuleArgs {
        try_first_pass: true,
        use_first_pass: false,
    };

    assert!(decide_first_pass(args, Some("1234"), &strict).is_prompt_user());
    assert!(decide_first_pass(args, Some("12345678"), &strict).is_prompt_user());
    assert!(decide_first_pass(args, Some("123456"), &strict).is_try_first_pass());
}

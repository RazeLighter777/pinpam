use std::process::Command;

#[test]
fn machine_length_serializes_username_errors_without_opening_the_tpm() {
    let output = Command::new(env!("CARGO_BIN_EXE_pinutil"))
        .args(["--machine", "length", "pinpam-no-such-user-length-test"])
        .output()
        .expect("run pinutil");
    assert!(!output.status.success());
    let result: serde_json::Value = serde_json::from_slice(&output.stdout)
        .expect("machine errors must produce a JSON result on stdout");
    assert_eq!(result, serde_json::json!({"Err": "UserNotFound"}));
}

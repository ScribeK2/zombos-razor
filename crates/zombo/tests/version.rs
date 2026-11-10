#![allow(clippy::unwrap_used)]
use std::process::Command;

#[test]
fn version_flag_prints_the_name_and_the_stamped_version() {
    let out = Command::new(env!("CARGO_BIN_EXE_zombo")).arg("--version").output().unwrap();
    assert!(out.status.success(), "{out:?}");
    assert_eq!(String::from_utf8_lossy(&out.stdout), format!("zombo {}\n", zombo_core::VERSION));
}

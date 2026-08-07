//! Every NixOS VM suite, as a test nextest can run.
//!
//! ```
//! cargo nextest run --profile vm
//! cargo nextest run --profile vm -E 'test(endtoend)'
//! ```
//!
//! Each shells out to `nix build` for one flake check, so nothing here duplicates the assertions —
//! it exists so one runner covers both layers. They boot real machines and take minutes; the
//! default nextest profile excludes them, plain `cargo test` does not.

use std::process::Command;

/// Kept in sync with the flake by `the_suite_list_matches_the_flake`, so a suite added there and
/// forgotten here is a failure rather than silent under-coverage.
const SUITES: &[&str] = &[
    // The product surface: the shipped binary, a secret file, and a machine name.
    "transport",
    "endtoend",
    "control",
    "hostile",
    "status",
    "resilience",
    "module",
    // One half in isolation, which the shipped binary deliberately cannot do.
    "laptop",
    "isolation",
    "datapath-ethernet",
    "datapath-wireguard",
];

/// 6.18 is the target; latest is a forward-compatibility check. A helper permitted in one and not
/// the other would otherwise show up only on the machine you actually run.
const KERNELS: &[&str] = &["6_18", "latest"];

/// Not a suite × kernel cross-product: `demo` exists to be booted, so it runs on 6.18 only.
const STANDALONE: &[&str] = &["demo"];

fn system() -> &'static str {
    if cfg!(target_arch = "aarch64") {
        "aarch64-linux"
    } else {
        "x86_64-linux"
    }
}

fn repo_root() -> std::path::PathBuf {
    // CARGO_MANIFEST_DIR is crates/needlecast.
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("repo root")
        .to_path_buf()
}

fn nix(args: &[&str]) -> std::process::Output {
    Command::new("nix")
        .args(args)
        .current_dir(repo_root())
        .output()
        .expect("nix is on PATH; run inside the devshell")
}

fn build_check(name: &str) {
    let attr = format!(".#checks.{}.{}", system(), name);
    let out = nix(&["build", &attr, "--no-link", "--print-build-logs"]);
    if !out.status.success() {
        panic!(
            "{attr} failed ({})\n--- stderr ---\n{}",
            out.status,
            String::from_utf8_lossy(&out.stderr)
        );
    }
}

#[test]
fn the_suite_list_matches_the_flake() {
    let attr = format!(".#checks.{}", system());
    let out = nix(&["eval", &attr, "--apply", "builtins.attrNames", "--json"]);
    assert!(
        out.status.success(),
        "nix eval failed:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let listed: Vec<String> =
        serde_json::from_slice(&out.stdout).expect("nix eval emits a JSON array");

    let mut expected: Vec<String> = SUITES
        .iter()
        .flat_map(|s| KERNELS.iter().map(move |k| format!("{s}-{k}")))
        .chain(STANDALONE.iter().map(|s| s.to_string()))
        .collect();
    expected.sort();
    let mut listed = listed;
    listed.sort();

    assert_eq!(
        listed, expected,
        "flake checks and the SUITES/KERNELS lists in this file have diverged"
    );
}

macro_rules! vm_suite {
    ($($fn_name:ident => $check:literal),* $(,)?) => {
        $(
            #[test]
            fn $fn_name() {
                build_check($check);
            }
        )*
    };
}

vm_suite! {
    transport_6_18 => "transport-6_18",
    transport_latest => "transport-latest",
    endtoend_6_18 => "endtoend-6_18",
    endtoend_latest => "endtoend-latest",
    control_6_18 => "control-6_18",
    control_latest => "control-latest",
    hostile_6_18 => "hostile-6_18",
    hostile_latest => "hostile-latest",
    status_6_18 => "status-6_18",
    status_latest => "status-latest",
    resilience_6_18 => "resilience-6_18",
    resilience_latest => "resilience-latest",
    module_6_18 => "module-6_18",
    module_latest => "module-latest",
    laptop_6_18 => "laptop-6_18",
    laptop_latest => "laptop-latest",
    isolation_6_18 => "isolation-6_18",
    isolation_latest => "isolation-latest",
    datapath_ethernet_6_18 => "datapath-ethernet-6_18",
    datapath_ethernet_latest => "datapath-ethernet-latest",
    datapath_wireguard_6_18 => "datapath-wireguard-6_18",
    datapath_wireguard_latest => "datapath-wireguard-latest",
    demo => "demo",
}

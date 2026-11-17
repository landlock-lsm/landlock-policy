// SPDX-License-Identifier: Apache-2.0 OR MIT

use crate::{parser::LATEST_ABI, policy::RulesetMasks, Policy};
use landlock::{Access, AccessFs, LandlockStatus, RulesetStatus, ABI};
use std::{fs::File, io::ErrorKind, net::TcpListener};

fn test_kernel_abi(test_name: &str) -> Option<i32> {
    let value = match std::env::var("LANDLOCK_CRATE_TEST_ABI") {
        Ok(value) => value,
        Err(std::env::VarError::NotPresent) => {
            eprintln!("Skipping {test_name}: LANDLOCK_CRATE_TEST_ABI is not set");
            return None;
        }
        Err(error) => panic!("Invalid LANDLOCK_CRATE_TEST_ABI: {error}"),
    };
    let abi = value
        .parse::<i32>()
        .unwrap_or_else(|error| panic!("Invalid LANDLOCK_CRATE_TEST_ABI {value:?}: {error}"));
    if abi < 0 {
        panic!("Invalid LANDLOCK_CRATE_TEST_ABI {value:?}: expected a non-negative integer");
    }
    Some(abi)
}

fn required_abi_for_default_policy(effective_abi: ABI) -> i32 {
    // RulesetStatus follows the kernel features requested by the built ruleset,
    // not policy ABI metadata. Walk backward through the monotonically growing
    // ABI masks to find the oldest ABI supporting every default mask. Using the
    // aggregate keeps new represented categories in this oracle through
    // RulesetMasks' exhaustive construction and intersection.
    let masks = RulesetMasks::from_all(effective_abi);

    let mut required_abi = effective_abi as i32;
    for candidate in (1..=required_abi).rev() {
        let candidate_masks = RulesetMasks::from_all(ABI::from(candidate));

        if candidate_masks & masks != masks {
            break;
        }
        required_abi = candidate;
    }
    required_abi
}

#[test]
fn test_required_abi_for_default_policy() {
    for (effective_abi, required_abi) in [
        (ABI::V1, ABI::V1),
        (ABI::V2, ABI::V2),
        (ABI::V3, ABI::V3),
        (ABI::V4, ABI::V4),
        (ABI::V5, ABI::V5),
        (ABI::V6, ABI::V6),
        (ABI::V7, ABI::V6),
    ] {
        assert_eq!(
            required_abi_for_default_policy(effective_abi),
            required_abi as i32
        );
    }
}

#[test]
fn test_kernel_abi_downgrade() {
    let Some(kernel_abi) = test_kernel_abi("test_kernel_abi_downgrade") else {
        return;
    };
    let latest = LATEST_ABI as i32;
    let readable_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml");
    File::open(&readable_path).unwrap();

    for requested_abi in (1..=latest).chain([latest + 1, i32::MAX]) {
        let readable_path = readable_path.clone();
        let (status, read_result) = std::thread::spawn(move || {
            let json = format!(
                r#"{{
                    "abi": {requested_abi}
                }}"#
            );
            let policy = Policy::parse_json(json.as_bytes()).unwrap();
            let resolved = policy.resolve().unwrap();
            let (ruleset, rule_errors) = resolved.build_ruleset().unwrap();
            assert!(rule_errors.is_empty());
            let status = ruleset.restrict_self().unwrap();
            let read_result = File::open(readable_path)
                .map(drop)
                .map_err(|error| error.kind());
            (status, read_result)
        })
        .join()
        .unwrap();

        let effective_abi = ABI::from(requested_abi.min(latest));
        let required_abi = required_abi_for_default_policy(effective_abi);
        let expected_ruleset = if kernel_abi == 0 {
            RulesetStatus::NotEnforced
        } else if kernel_abi >= required_abi {
            RulesetStatus::FullyEnforced
        } else {
            RulesetStatus::PartiallyEnforced
        };
        assert_eq!(status.ruleset, expected_ruleset);
        assert!(status.no_new_privs);
        assert_eq!(
            read_result,
            if kernel_abi == 0 {
                Ok(())
            } else {
                Err(ErrorKind::PermissionDenied)
            }
        );

        match status.landlock {
            LandlockStatus::NotEnabled | LandlockStatus::NotImplemented => {
                assert_eq!(kernel_abi, 0);
            }
            LandlockStatus::Available {
                effective_abi: kernel_effective_abi,
                kernel_abi: reported_kernel_abi,
            } => {
                assert!(kernel_abi > 0);
                assert_eq!(kernel_effective_abi, ABI::from(kernel_abi));
                assert_eq!(
                    reported_kernel_abi,
                    (kernel_abi != kernel_effective_abi as i32).then_some(kernel_abi)
                );
            }
        }
    }
}

#[test]
fn test_exception_kernel_abi_downgrade() {
    let Some(kernel_abi) = test_kernel_abi("test_exception_kernel_abi_downgrade") else {
        return;
    };

    let status = std::thread::spawn(|| {
        drop(
            TcpListener::bind(("127.0.0.1", 0))
                .expect("the runtime test requires local TCP bind support"),
        );
        let json = r#"{
            "abi": 5,
            "ruleset": [
                {
                    "unhandledAccessFs": [ "ioctl_dev" ],
                    "unhandledAccessNet": [ "abi.all" ]
                }
            ]
        }"#;
        let policy = Policy::parse_json(json.as_bytes()).unwrap();
        assert_eq!(
            policy.masks.fs,
            AccessFs::from_all(ABI::V5) & !AccessFs::IoctlDev
        );
        let resolved = policy.resolve().unwrap();
        let (ruleset, rule_errors) = resolved.build_ruleset().unwrap();
        assert!(rule_errors.is_empty());
        let status = ruleset.restrict_self().unwrap();
        let _listener = TcpListener::bind(("127.0.0.1", 0))
            .expect("excluded network access must remain unrestricted");
        status
    })
    .join()
    .unwrap();

    let expected = match kernel_abi {
        0 => RulesetStatus::NotEnforced,
        1 | 2 => RulesetStatus::PartiallyEnforced,
        _ => RulesetStatus::FullyEnforced,
    };
    assert_eq!(status.ruleset, expected);
    assert!(status.no_new_privs);
}

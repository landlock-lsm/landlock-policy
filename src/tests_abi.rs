// SPDX-License-Identifier: Apache-2.0 OR MIT

use crate::{
    parser::LATEST_ABI,
    policy::RulesetMasks,
    tests_helpers::{parse_json, parse_json_schema, parse_toml},
    Policy,
};
use landlock::{Access, AccessFs, AccessNet, BitFlags, Scope, ABI};
use serde_json::error::Category;

#[test]
fn test_represented_masks_by_abi() {
    let fs_v1 = AccessFs::Execute
        | AccessFs::WriteFile
        | AccessFs::ReadFile
        | AccessFs::ReadDir
        | AccessFs::RemoveDir
        | AccessFs::RemoveFile
        | AccessFs::MakeChar
        | AccessFs::MakeDir
        | AccessFs::MakeReg
        | AccessFs::MakeSock
        | AccessFs::MakeFifo
        | AccessFs::MakeBlock
        | AccessFs::MakeSym;
    let fs_v2 = fs_v1 | AccessFs::Refer;
    let fs_v3 = fs_v2 | AccessFs::Truncate;
    let fs_v5 = fs_v3 | AccessFs::IoctlDev;
    let net_v4 = AccessNet::BindTcp | AccessNet::ConnectTcp;
    let scope_v6 = Scope::AbstractUnixSocket | Scope::Signal;
    let no_net: BitFlags<AccessNet> = BitFlags::EMPTY;
    let no_scope: BitFlags<Scope> = BitFlags::EMPTY;

    for (abi, fs, net, scope) in [
        (ABI::V1, fs_v1, no_net, no_scope),
        (ABI::V2, fs_v2, no_net, no_scope),
        (ABI::V3, fs_v3, no_net, no_scope),
        (ABI::V4, fs_v3, net_v4, no_scope),
        (ABI::V5, fs_v5, net_v4, no_scope),
        (ABI::V6, fs_v5, net_v4, scope_v6),
        (ABI::V7, fs_v5, net_v4, scope_v6),
    ] {
        assert_eq!(AccessFs::from_all(abi), fs);
        assert_eq!(AccessNet::from_all(abi), net);
        assert_eq!(Scope::from_all(abi), scope);
    }
}

#[test]
fn test_latest_policy_abi() {
    assert_eq!(LATEST_ABI, ABI::V7);
    // A newer ABI may leave these represented category masks unchanged. When
    // increasing LATEST_ABI, keep the baseline at the most recent ABI that
    // changed one of them.
    assert_eq!(AccessFs::from_all(ABI::V6), AccessFs::from_all(LATEST_ABI));
    assert_eq!(
        AccessNet::from_all(ABI::V6),
        AccessNet::from_all(LATEST_ABI)
    );
    assert_eq!(Scope::from_all(ABI::V6), Scope::from_all(LATEST_ABI));
}

#[test]
fn test_latest_plus_one() {
    let requested = LATEST_ABI as i32 + 1;
    let json = format!(
        r#"{{
            "abi": {requested}
        }}"#
    );
    let toml = format!(
        r#"
        abi = {requested}
        "#
    );

    assert_eq!(parse_json(&json).unwrap(), Policy::new(LATEST_ABI));
    assert_eq!(parse_toml(&toml).unwrap(), Policy::new(LATEST_ABI));
}

#[test]
fn test_access_fs_with_value() {
    let json = r#"{
        "abi": 2,
        "ruleset": [
            {
                "unhandledAccessFs": [
                    "execute"
                    ]
            }
        ]
    }"#;
    let toml = r#"
        abi = 2
        [[ruleset]]
        unhandled_access_fs = [
            "execute",
        ]
    "#;

    let policy = Policy {
        masks: RulesetMasks {
            fs: AccessFs::from_all(ABI::V2) & !AccessFs::Execute,
            net: AccessNet::from_all(ABI::V2),
            scope: Scope::from_all(ABI::V2),
        },
        ..Policy::new(ABI::V2)
    };
    assert_eq!(parse_json(json).unwrap(), policy);
    assert_eq!(parse_toml(toml).unwrap(), policy);
}

#[test]
fn test_known_inverse_access_outside_abi_is_inert() {
    let json = r#"{
        "abi": 1,
        "ruleset": [{
            "unhandledAccessFs": ["refer", "truncate", "ioctl_dev"],
            "unhandledAccessNet": ["bind_tcp", "connect_tcp"],
            "unscoped": ["abstract_unix_socket", "signal"]
        }]
    }"#;
    let toml = r#"
        abi = 1
        [[ruleset]]
        unhandled_access_fs = ["refer", "truncate", "ioctl_dev"]
        unhandled_access_net = ["bind_tcp", "connect_tcp"]
        unscoped = ["abstract_unix_socket", "signal"]
    "#;

    assert_eq!(parse_json(json).unwrap(), Policy::new(ABI::V1));
    assert_eq!(parse_toml(toml).unwrap(), Policy::new(ABI::V1));
}

#[test]
fn test_known_allowance_access_outside_abi_is_inert() {
    let json = r#"{
        "abi": 1,
        "pathBeneath": [{
            "allowedAccess": ["refer", "truncate", "ioctl_dev"],
            "parent": ["."]
        }],
        "netPort": [{
            "allowedAccess": ["bind_tcp", "connect_tcp"],
            "port": [80]
        }]
    }"#;
    let toml = r#"
        abi = 1
        [[path_beneath]]
        allowed_access = ["refer", "truncate", "ioctl_dev"]
        parent = ["."]
        [[net_port]]
        allowed_access = ["bind_tcp", "connect_tcp"]
        port = [80]
    "#;

    assert_eq!(parse_json(json).unwrap(), Policy::new(ABI::V1));
    assert_eq!(parse_toml(toml).unwrap(), Policy::new(ABI::V1));
}

#[test]
fn test_future_abi_concrete_access() {
    let json = format!(
        r#"{{
            "abi": {},
            "ruleset": [{{
                "unhandledAccessFs": ["execute"],
                "unhandledAccessNet": ["bind_tcp"],
                "unscoped": ["signal"]
            }}]
        }}"#,
        i32::MAX
    );
    let toml = format!(
        r#"
            abi = {}
            [[ruleset]]
            unhandled_access_fs = ["execute"]
            unhandled_access_net = ["bind_tcp"]
            unscoped = ["signal"]
        "#,
        i32::MAX
    );
    let policy = Policy {
        masks: RulesetMasks {
            fs: AccessFs::from_all(LATEST_ABI) & !AccessFs::Execute,
            net: AccessNet::ConnectTcp.into(),
            scope: Scope::AbstractUnixSocket.into(),
        },
        ..Policy::new(LATEST_ABI)
    };
    assert_eq!(parse_json(&json).unwrap(), policy);
    assert_eq!(parse_toml(&toml).unwrap(), policy);
}

#[test]
fn test_group_only_no_op() {
    let json = r#"{
        "abi": 3,
        "ruleset": [{
            "unhandledAccessFs": ["execute"],
            "unhandledAccessNet": ["abi.all"],
            "unscoped": ["abi.all"]
        }],
        "netPort": [{
            "allowedAccess": ["abi.all"],
            "port": [80]
        }]
    }"#;
    let toml = r#"
        abi = 3
        [[ruleset]]
        unhandled_access_fs = ["execute"]
        unhandled_access_net = ["abi.all"]
        unscoped = ["abi.all"]
        [[net_port]]
        allowed_access = ["abi.all"]
        port = [80]
    "#;
    let policy = Policy {
        masks: RulesetMasks {
            fs: AccessFs::from_all(ABI::V3) & !AccessFs::Execute,
            net: AccessNet::from_all(ABI::V3),
            scope: Scope::from_all(ABI::V3),
        },
        ..Policy::new(ABI::V3)
    };
    assert_eq!(parse_json(json).unwrap(), policy);
    assert_eq!(parse_toml(toml).unwrap(), policy);
}

#[test]
fn test_missing() {
    let json = r#"{
        "ruleset": [
            {
                "unhandledAccessFs": [
                    "abi.all"
                    ]
            }
        ]
    }"#;
    let toml = r#"
        [[ruleset]]
        unhandled_access_fs = [
            "abi.all",
        ]
    "#;

    assert_eq!(parse_json(json), Err(Category::Data));
    assert!(parse_toml(toml).is_err());
}

#[test]
fn test_abi_only() {
    let json = r#"{
        "abi": 1
    }"#;
    let toml = r#"
        abi = 1
    "#;

    assert_eq!(parse_json(json).unwrap(), Policy::new(ABI::V1));
    assert_eq!(parse_toml(toml).unwrap(), Policy::new(ABI::V1));
}

#[test]
fn test_non_integer() {
    let json = r#"{
        "abi": "6",
        "ruleset": [
            {
                "unhandledAccessFs": ["execute"]
            }
        ]
    }"#;
    let toml = r#"
        abi = "6"
        [[ruleset]]
        unhandled_access_fs = ["execute"]
    "#;

    assert_eq!(parse_json(json), Err(Category::Data));
    assert!(parse_toml(toml).is_err());
}

#[test]
fn test_format_ok() {
    let json = r#"{
        "abi": 1,
        "ruleset": [
            {
                "unhandledAccessFs": [ "execute" ]
            }
        ]
    }"#;
    let toml = r#"
        abi = 1
        [[ruleset]]
        unhandled_access_fs = [
            "execute",
        ]
    "#;

    let policy = Policy {
        masks: RulesetMasks {
            fs: AccessFs::from_all(ABI::V1) & !AccessFs::Execute,
            net: AccessNet::from_all(ABI::V1),
            scope: Scope::from_all(ABI::V1),
        },
        ..Policy::new(ABI::V1)
    };
    assert_eq!(parse_json(json).unwrap(), policy);
    assert_eq!(parse_toml(toml).unwrap(), policy);
}

#[test]
fn test_dup_abi() {
    let json = r#"{
        "abi": 1,
        "abi": 1,
        "ruleset": [
            {
                "unhandledAccessFs": [ "execute" ]
            }
        ]
    }"#;
    let toml = r#"
        abi = 1
        abi = 1
        [[ruleset]]
        unhandled_access_fs = [
            "execute",
        ]
    "#;

    // Test that duplicate 'abi' fields are rejected by the parser.  Uses
    // parse_json_schema(json, false) because duplicate field rejection is a
    // parser-level concern, not schema-level (JSON schema assumes valid JSON).
    assert_eq!(parse_json_schema(json, false), Err(Category::Data));
    assert!(parse_toml(toml).is_err());
}

#[test]
fn test_all_versions_abi_defaults() {
    for version in 1..=(LATEST_ABI as i32) {
        let json = format!(
            r#"{{
                "abi": {version}
            }}"#
        );
        let toml = format!(
            r#"
                abi = {version}
            "#
        );

        let abi = version.into();
        let policy = Policy::new(abi);
        println!("Testing ABI {version} and expecting {policy:?}");
        assert_eq!(parse_json(&json).unwrap(), policy);
        assert_eq!(parse_toml(&toml).unwrap(), policy);
    }
}

#[test]
fn test_all_versions_abi_read_execute() {
    for version in 1..=(LATEST_ABI as i32) {
        let json = format!(
            r#"{{
                "abi": {},
                "ruleset": [
                    {{
                        "unhandledAccessFs": [ "abi.read_execute" ]
                    }}
                ],
                "pathBeneath": [
                    {{
                        "allowedAccess": [ "abi.read_execute" ],
                        "parent": [ "." ]
                    }}
                ]
            }}"#,
            version
        );
        let toml = format!(
            r#"
            abi = {}
            [[ruleset]]
            unhandled_access_fs = [ "abi.read_execute" ]
            [[path_beneath]]
            allowed_access = [ "abi.read_execute" ]
            parent = [ "." ]
            "#,
            version
        );

        let abi = version.into();
        let policy = Policy {
            masks: RulesetMasks {
                fs: AccessFs::from_write(abi) & !AccessFs::Refer,
                net: AccessNet::from_all(abi),
                scope: Scope::from_all(abi),
            },
            ..Policy::new(abi)
        };
        println!("Testing ABI {version} read_execute and expecting {policy:?}");
        assert_eq!(parse_json(&json).unwrap(), policy);
        assert_eq!(parse_toml(&toml).unwrap(), policy);
    }
}

#[test]
fn test_all_versions_abi_read_write() {
    for version in 1..=(LATEST_ABI as i32) {
        let json = format!(
            r#"{{
                "abi": {},
                "ruleset": [
                    {{
                        "unhandledAccessFs": [ "abi.read_write" ]
                    }}
                ],
                "pathBeneath": [
                    {{
                        "allowedAccess": [ "abi.read_write" ],
                        "parent": [ "." ]
                    }}
                ]
            }}"#,
            version
        );
        let toml = format!(
            r#"
            abi = {}
            [[ruleset]]
            unhandled_access_fs = [ "abi.read_write" ]
            [[path_beneath]]
            allowed_access = [ "abi.read_write" ]
            parent = [ "." ]
            "#,
            version
        );

        let abi = version.into();
        let policy = Policy {
            masks: RulesetMasks {
                fs: AccessFs::Execute.into(),
                net: AccessNet::from_all(abi),
                scope: Scope::from_all(abi),
            },
            ..Policy::new(abi)
        };
        println!("Testing ABI {version} read_write and expecting {policy:?}");
        assert_eq!(parse_json(&json).unwrap(), policy);
        assert_eq!(parse_toml(&toml).unwrap(), policy);
    }
}

#[test]
fn test_zero() {
    let json = r#"{
        "abi": 0
    }"#;
    let toml = r#"
        abi = 0
    "#;

    assert_eq!(parse_json(json), Err(Category::Data));
    assert!(parse_toml(toml).is_err());
}

#[test]
fn test_negative() {
    let json = r#"{
        "abi": -1
    }"#;
    let toml = r#"
        abi = -1
    "#;

    assert_eq!(parse_json(json), Err(Category::Data));
    assert!(parse_toml(toml).is_err());
}

#[test]
fn test_i32() {
    // 2^31 - 1
    let json = r#"{
        "abi": 2147483647
    }"#;
    let toml = r#"
        abi = 2147483647
    "#;

    assert_eq!(parse_json(json).unwrap(), Policy::new(LATEST_ABI));
    assert_eq!(parse_toml(toml).unwrap(), Policy::new(LATEST_ABI));
}

#[test]
fn test_future_abi_unknown_syntax() {
    let json = [
        r#"{
            "abi": 2147483647,
            "ruleset": [
                {
                    "unhandledAccessFs": ["future_right"]
                }
            ]
        }"#,
        r#"{
            "abi": 2147483647,
            "ruleset": [
                {
                    "futureAccess": ["execute"]
                }
            ]
        }"#,
        r#"{
            "abi": 2147483647,
            "futureRule": []
        }"#,
    ];
    let toml = [
        r#"
            abi = 2147483647
            [[ruleset]]
            unhandled_access_fs = ["future_right"]
        "#,
        r#"
            abi = 2147483647
            [[ruleset]]
            future_access = ["execute"]
        "#,
        r#"
            abi = 2147483647
            [[future_rule]]
        "#,
    ];

    for json in json {
        assert_eq!(parse_json(json), Err(Category::Data));
    }
    for toml in toml {
        assert!(parse_toml(toml).is_err());
    }
}

#[test]
fn test_p31() {
    // 2^31
    let json = r#"{
        "abi": 2147483648
    }"#;
    let toml = r#"
        abi = 2147483648
    "#;

    assert_eq!(parse_json(json), Err(Category::Data));
    assert!(parse_toml(toml).is_err());
}

#[test]
fn test_p32() {
    // 2^32
    let json = r#"{
        "abi": 4294967295
    }"#;
    let toml = r#"
        abi = 4294967295
    "#;

    assert_eq!(parse_json(json), Err(Category::Data));
    assert!(parse_toml(toml).is_err());
}

#[test]
fn test_p64() {
    // 2^64
    let json = r#"{
        "abi": 18446744073709551616
    }"#;
    let toml = r#"
        abi = 18446744073709551616
    "#;

    assert_eq!(parse_json(json), Err(Category::Data));
    assert!(parse_toml(toml).is_err());
}

#[test]
fn test_p128() {
    // 2^128
    let json = r#"{
        "abi": 340282366920938463463374607431768211456
    }"#;
    let toml = r#"
        abi = 340282366920938463463374607431768211456
    "#;

    assert_eq!(parse_json(json), Err(Category::Data));
    assert!(parse_toml(toml).is_err());
}

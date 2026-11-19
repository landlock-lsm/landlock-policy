// SPDX-License-Identifier: Apache-2.0 OR MIT

use crate::{
    parser::{TemplateString, LATEST_ABI},
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
            "abi": {requested},
            "ruleset": [
                {{
                    "handledAccessFs": ["abi.all"]
                }}
            ]
        }}"#
    );
    let toml = format!(
        r#"
        abi = {requested}
        [[ruleset]]
        handled_access_fs = ["abi.all"]
        "#
    );
    let config = Policy {
        masks: RulesetMasks {
            fs: AccessFs::from_all(LATEST_ABI),
            ..Default::default()
        },
        ..Policy::empty(LATEST_ABI)
    };

    assert_eq!(parse_json(&json).unwrap(), config);
    assert_eq!(parse_toml(&toml).unwrap(), config);
}

#[test]
fn test_access_fs_with_value() {
    let json = r#"{
        "abi": 2,
        "ruleset": [
            {
                "handledAccessFs": [
                    "abi.all"
                    ]
            }
        ]
    }"#;
    let toml = r#"
        abi = 2
        [[ruleset]]
        handled_access_fs = [
            "abi.all",
        ]
    "#;

    let policy = Policy {
        masks: RulesetMasks {
            fs: AccessFs::from_all(ABI::V2),
            ..Default::default()
        },
        ..Policy::empty(ABI::V2)
    };
    assert_eq!(parse_json(json).unwrap(), policy);
    assert_eq!(parse_toml(toml).unwrap(), policy);
}

#[test]
fn test_missing() {
    let json = r#"{
        "ruleset": [
            {
                "handledAccessFs": [
                    "abi.all"
                    ]
            }
        ]
    }"#;
    let toml = r#"
        [[ruleset]]
        handled_access_fs = [
            "abi.all",
        ]
    "#;

    assert_eq!(parse_json(json), Err(Category::Data));
    assert!(parse_toml(toml).is_err());
}

#[test]
fn test_format_error() {
    let json = r#"{
        "abi": 1
    }"#;
    let toml = r#"
        abi = 1
    "#;

    assert_eq!(parse_json(json), Err(Category::Data));
    assert!(parse_toml(toml).is_err());
}

#[test]
fn test_non_integer() {
    let json = r#"{
        "abi": "6",
        "ruleset": [
            {
                "handledAccessFs": ["execute"]
            }
        ]
    }"#;
    let toml = r#"
        abi = "6"
        [[ruleset]]
        handled_access_fs = ["execute"]
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
                "handledAccessFs": [ "execute" ]
            }
        ]
    }"#;
    let toml = r#"
        abi = 1
        [[ruleset]]
        handled_access_fs = [
            "execute",
        ]
    "#;

    let policy = Policy {
        masks: RulesetMasks {
            fs: AccessFs::Execute.into(),
            ..Default::default()
        },
        ..Policy::empty(ABI::V1)
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
                "handledAccessFs": [ "execute" ]
            }
        ]
    }"#;
    let toml = r#"
        abi = 1
        abi = 1
        [[ruleset]]
        handled_access_fs = [
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
fn test_all_versions_abi_all() {
    for version in 1..=(LATEST_ABI as i32) {
        let json = format!(
            r#"{{
                "abi": {},
                "ruleset": [
                    {{
                        "handledAccessFs": [ "abi.all" ],
                        "handledAccessNet": [ "abi.all" ],
                        "scoped": [ "abi.all" ]
                    }}
                ],
                "pathBeneath": [
                    {{
                        "allowedAccess": [ "abi.all" ],
                        "parent": [ "." ]
                    }}
                ],
                "netPort": [
                    {{
                        "allowedAccess": [ "abi.all" ],
                        "port": [ 1 ]
                    }}
                ]
            }}"#,
            version
        );
        let toml = format!(
            r#"
            abi = {}
            [[ruleset]]
            handled_access_fs = [ "abi.all" ]
            handled_access_net = [ "abi.all" ]
            scoped = [ "abi.all" ]
            [[path_beneath]]
            allowed_access = [ "abi.all" ]
            parent = [ "." ]
            [[net_port]]
            allowed_access = [ "abi.all" ]
            port = [ 1 ]
            "#,
            version
        );

        let abi = version.into();
        let mut policy = Policy {
            masks: RulesetMasks {
                fs: AccessFs::from_all(abi),
                net: AccessNet::from_all(abi),
                scope: Scope::from_all(abi),
            },
            rules_path_beneath: [(TemplateString::from_text("."), AccessFs::from_all(abi))].into(),
            ..Policy::empty(abi)
        };
        if abi >= ABI::V4 {
            // Do not add rules with empty access right.
            policy.rules_net_port = [(1, AccessNet::from_all(abi))].into();
        }
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
                        "handledAccessFs": [ "abi.read_execute" ]
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
            handled_access_fs = [ "abi.read_execute" ]
            [[path_beneath]]
            allowed_access = [ "abi.read_execute" ]
            parent = [ "." ]
            "#,
            version
        );

        let abi = version.into();
        let expected_access =
            AccessFs::from_read(abi) | (AccessFs::from_all(abi) & AccessFs::Refer);

        let policy = Policy {
            masks: RulesetMasks {
                fs: expected_access,
                ..Default::default()
            },
            rules_path_beneath: [(TemplateString::from_text("."), expected_access)].into(),
            ..Policy::empty(abi)
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
                        "handledAccessFs": [ "abi.read_write" ]
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
            handled_access_fs = [ "abi.read_write" ]
            [[path_beneath]]
            allowed_access = [ "abi.read_write" ]
            parent = [ "." ]
            "#,
            version
        );

        let abi = version.into();
        let expected_access = AccessFs::from_all(abi) & !AccessFs::Execute;

        let policy = Policy {
            masks: RulesetMasks {
                fs: expected_access,
                ..Default::default()
            },
            rules_path_beneath: [(TemplateString::from_text("."), expected_access)].into(),
            ..Policy::empty(abi)
        };
        println!("Testing ABI {version} read_write and expecting {policy:?}");
        assert_eq!(parse_json(&json).unwrap(), policy);
        assert_eq!(parse_toml(&toml).unwrap(), policy);
    }
}

#[test]
fn test_zero() {
    let json = r#"{
        "abi": 0,
        "ruleset": [
            {
                "handledAccessFs": [ "execute" ]
            }
        ]
    }"#;
    let toml = r#"
        abi = 0
        [[ruleset]]
        handled_access_fs = [
            "execute",
        ]
    "#;

    assert_eq!(parse_json(json), Err(Category::Data));
    assert!(parse_toml(toml).is_err());
}

#[test]
fn test_negative() {
    let json = r#"{
        "abi": -1,
        "ruleset": [
            {
                "handledAccessFs": [ "execute" ]
            }
        ]
    }"#;
    let toml = r#"
        abi = -1
        [[ruleset]]
        handled_access_fs = [
            "execute",
        ]
    "#;

    assert_eq!(parse_json(json), Err(Category::Data));
    assert!(parse_toml(toml).is_err());
}

#[test]
fn test_i32() {
    // 2^31 - 1
    let json = r#"{
        "abi": 2147483647,
        "ruleset": [
            {
                "handledAccessFs": [ "abi.all" ]
            }
        ]
    }"#;
    let toml = r#"
        abi = 2147483647
        [[ruleset]]
        handled_access_fs = [
            "abi.all",
        ]
    "#;
    let policy = Policy {
        masks: RulesetMasks {
            fs: AccessFs::from_all(LATEST_ABI),
            ..Default::default()
        },
        ..Policy::empty(LATEST_ABI)
    };
    assert_eq!(parse_json(json).unwrap(), policy);
    assert_eq!(parse_toml(toml).unwrap(), policy);
}

#[test]
fn test_future_abi_unknown_syntax() {
    let json = [
        r#"{
            "abi": 2147483647,
            "ruleset": [
                {
                    "handledAccessFs": ["future_right"]
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
            handled_access_fs = ["future_right"]
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
        "abi": 2147483648,
        "ruleset": [
            {
                "handledAccessFs": [ "abi.all" ]
            }
        ]
    }"#;
    let toml = r#"
        abi = 2147483648
        [[ruleset]]
        handled_access_fs = [
            "abi.all",
        ]
    "#;

    assert_eq!(parse_json(json), Err(Category::Data));
    assert!(parse_toml(toml).is_err());
}

#[test]
fn test_p32() {
    // 2^32
    let json = r#"{
        "abi": 4294967295,
        "ruleset": [
            {
                "handledAccessFs": [ "execute" ]
            }
        ]
    }"#;
    let toml = r#"
        abi = 4294967295
        [[ruleset]]
        handled_access_fs = [
            "execute",
        ]
    "#;

    assert_eq!(parse_json(json), Err(Category::Data));
    assert!(parse_toml(toml).is_err());
}

#[test]
fn test_p64() {
    // 2^64
    let json = r#"{
        "abi": 18446744073709551616,
        "ruleset": [
            {
                "handledAccessFs": [ "execute" ]
            }
        ]
    }"#;
    let toml = r#"
        abi = 18446744073709551616
        [[ruleset]]
        handled_access_fs = [
            "execute",
        ]
    "#;

    assert_eq!(parse_json(json), Err(Category::Data));
    assert!(parse_toml(toml).is_err());
}

#[test]
fn test_p128() {
    // 2^128
    let json = r#"{
        "abi": 340282366920938463463374607431768211456,
        "ruleset": [
            {
                "handledAccessFs": [ "execute" ]
            }
        ]
    }"#;
    let toml = r#"
        abi = 340282366920938463463374607431768211456
        [[ruleset]]
        handled_access_fs = [
            "execute",
        ]
    "#;

    assert_eq!(parse_json(json), Err(Category::Data));
    assert!(parse_toml(toml).is_err());
}

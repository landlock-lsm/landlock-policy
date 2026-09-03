// SPDX-License-Identifier: Apache-2.0 OR MIT

use crate::{
    parser::{TemplateString, LATEST_ABI},
    policy::{ParseJsonError, ParseTomlError, PolicyError, RulesetMasks},
    tests_helpers::{parse_json, parse_json_schema, parse_toml},
    Policy,
};
use landlock::{Access, AccessFs, AccessNet, BitFlags, Scope, ABI};
use serde_json::error::Category;

#[test]
fn test_allowance_groups_at_all_abis() {
    for version in 1..=(LATEST_ABI as i32) {
        let json = format!(
            r#"{{
                "abi": {version},
                "pathBeneath": [
                    {{
                        "allowedAccess": [ "abi.read_execute" ],
                        "parent": [ "." ]
                    }}
                ],
                "netPort": [
                    {{
                        "allowedAccess": [ "abi.all" ],
                        "port": [ 80 ]
                    }}
                ]
            }}"#
        );
        let toml = format!(
            r#"
                abi = {version}
                [[path_beneath]]
                allowed_access = [ "abi.read_execute" ]
                parent = [ "." ]
                [[net_port]]
                allowed_access = [ "abi.all" ]
                port = [ 80 ]
            "#
        );
        let abi = ABI::from(version);
        let fs_access = AccessFs::from_read(abi) | (AccessFs::from_all(abi) & AccessFs::Refer);
        let mut expected = Policy {
            rules_path_beneath: [(TemplateString::from_text("."), fs_access)].into(),
            ..Policy::new(abi)
        };
        if abi >= ABI::V4 {
            expected.rules_net_port = [(80, AccessNet::from_all(abi))].into();
        }

        assert_eq!(parse_json(&json).unwrap(), expected);
        assert_eq!(parse_toml(&toml).unwrap(), expected);
    }
}

#[test]
fn test_inverse_identity_values() {
    for json in [
        r#"{
            "abi": 6,
            "ruleset": [
                {
                    "unhandledAccessFs": [],
                    "unhandledAccessNet": null,
                    "unscoped": []
                }
            ]
        }"#,
        r#"{
            "abi": 6,
            "ruleset": [ {} ]
        }"#,
        r#"{
            "abi": 6,
            "ruleset": [
                {
                    "unhandledAccessFs": null,
                    "unhandledAccessNet": null,
                    "unscoped": null
                }
            ]
        }"#,
    ] {
        assert_eq!(parse_json(json).unwrap(), Policy::new(ABI::V6));
    }

    for toml in [
        r#"
            abi = 6
            [[ruleset]]
            unhandled_access_fs = []
            unhandled_access_net = []
            unscoped = []
        "#,
        r#"
            abi = 6
            [[ruleset]]
        "#,
    ] {
        assert_eq!(parse_toml(toml).unwrap(), Policy::new(ABI::V6));
    }
}

#[test]
fn test_inverse_union_is_idempotent() {
    let json = r#"{
        "abi": 4,
        "ruleset": [
            {
                "unhandledAccessFs": [ "abi.all", "ioctl_dev", "abi.all" ]
            },
            {
                "unhandledAccessFs": [ "execute", "abi.all" ],
                "unhandledAccessNet": [ "connect_tcp" ]
            },
            {
                "unhandledAccessNet": [ "connect_tcp" ]
            },
            {
                "unscoped": [ "abi.all", "signal", "abi.all" ]
            }
        ]
    }"#;
    let toml = r#"
        abi = 4
        [[ruleset]]
        unhandled_access_fs = [ "abi.all", "ioctl_dev", "abi.all" ]
        [[ruleset]]
        unhandled_access_fs = [ "execute", "abi.all" ]
        unhandled_access_net = [ "connect_tcp" ]
        [[ruleset]]
        unhandled_access_net = [ "connect_tcp" ]
        [[ruleset]]
        unscoped = [ "abi.all", "signal", "abi.all" ]
    "#;

    let expected = Policy {
        masks: RulesetMasks {
            fs: Default::default(),
            net: AccessNet::BindTcp.into(),
            scope: Scope::from_all(ABI::V4),
        },
        ..Policy::new(ABI::V4)
    };

    assert_eq!(parse_json(json).unwrap(), expected);
    assert_eq!(parse_toml(toml).unwrap(), expected);
}

#[test]
fn test_obsolete_and_alternative_syntax_is_rejected() {
    for json in [
        r#"{
            "abi": 6,
            "ruleset": [
                {
                    "handledAccessFs": [ "execute" ]
                }
            ]
        }"#,
        r#"{
            "abi": 6,
            "ruleset": [
                {
                    "unhandledAccessFs": [ "-execute" ]
                }
            ]
        }"#,
        r#"{
            "abi": 6,
            "ruleset": [
                {
                    "unhandledAccessFs": {
                        "except": [ "execute" ]
                    }
                }
            ]
        }"#,
        r#"{
            "abi": 6,
            "ruleset": [
                {
                    "handledAccessFsExcept": [ "execute" ]
                }
            ]
        }"#,
    ] {
        assert_eq!(parse_json(json), Err(Category::Data));
    }

    for toml in [
        r#"
            abi = 6
            [[ruleset]]
            handled_access_fs = [ "execute" ]
        "#,
        r#"
            abi = 6
            [[ruleset]]
            unhandled_access_fs = [ "-execute" ]
        "#,
        r#"
            abi = 6
            [[ruleset.unhandled_access_fs]]
            except = [ "execute" ]
        "#,
        r#"
            abi = 6
            [[ruleset]]
            handled_access_fs_except = [ "execute" ]
        "#,
    ] {
        assert!(parse_toml(toml).is_err());
    }
}

#[test]
fn test_allowance_overlap_is_masked() {
    let json = r#"{
        "abi": 6,
        "ruleset": [
            {
                "unhandledAccessFs": [ "execute", "read_file" ],
                "unhandledAccessNet": [ "bind_tcp" ]
            }
        ],
        "pathBeneath": [
            {
                "allowedAccess": [ "abi.read_execute", "execute" ],
                "parent": [ "." ]
            }
        ],
        "netPort": [
            {
                "allowedAccess": [ "abi.all", "bind_tcp" ],
                "port": [ 80 ]
            }
        ]
    }"#;
    let toml = r#"
        abi = 6
        [[ruleset]]
        unhandled_access_fs = [ "execute", "read_file" ]
        unhandled_access_net = [ "bind_tcp" ]
        [[path_beneath]]
        allowed_access = [ "abi.read_execute", "execute" ]
        parent = [ "." ]
        [[net_port]]
        allowed_access = [ "abi.all", "bind_tcp" ]
        port = [ 80 ]
    "#;
    let expected = Policy {
        masks: RulesetMasks {
            fs: AccessFs::from_all(ABI::V6) & !(AccessFs::Execute | AccessFs::ReadFile),
            net: AccessNet::ConnectTcp.into(),
            scope: Scope::from_all(ABI::V6),
        },
        rules_path_beneath: [(
            TemplateString::from_text("."),
            (AccessFs::from_read(ABI::V6) | AccessFs::Refer)
                & !(AccessFs::Execute | AccessFs::ReadFile),
        )]
        .into(),
        rules_net_port: [(80, AccessNet::ConnectTcp.into())].into(),
        ..Policy::new(ABI::V6)
    };

    assert_eq!(parse_json(json).unwrap(), expected);
    assert_eq!(parse_toml(toml).unwrap(), expected);
}

#[test]
fn test_rules_in_all_unhandled_category_are_skipped() {
    let json = r#"{
        "abi": 6,
        "ruleset": [
            {
                "unhandledAccessFs": [ "abi.all" ],
                "unhandledAccessNet": [ "abi.all" ]
            }
        ],
        "pathBeneath": [
            {
                "allowedAccess": [ "execute" ],
                "parent": [ "." ]
            }
        ],
        "netPort": [
            {
                "allowedAccess": [ "abi.all" ],
                "port": [ 80 ]
            }
        ]
    }"#;
    let toml = r#"
        abi = 6
        [[ruleset]]
        unhandled_access_fs = [ "abi.all" ]
        unhandled_access_net = [ "abi.all" ]
        [[path_beneath]]
        allowed_access = [ "execute" ]
        parent = [ "." ]
        [[net_port]]
        allowed_access = [ "abi.all" ]
        port = [ 80 ]
    "#;
    let expected = Policy {
        masks: RulesetMasks {
            fs: Default::default(),
            net: Default::default(),
            scope: Scope::from_all(ABI::V6),
        },
        ..Policy::new(ABI::V6)
    };

    assert_eq!(parse_json(json).unwrap(), expected);
    assert_eq!(parse_toml(toml).unwrap(), expected);
}

#[test]
fn test_refer_exclusion_and_allowance_are_exact() {
    let json = r#"{
        "abi": 6,
        "ruleset": [
            {
                "unhandledAccessFs": [ "refer" ]
            }
        ],
        "pathBeneath": [
            {
                "allowedAccess": [ "refer" ],
                "parent": [ "." ]
            }
        ]
    }"#;
    let toml = r#"
        abi = 6
        [[ruleset]]
        unhandled_access_fs = [ "refer" ]
        [[path_beneath]]
        allowed_access = [ "refer" ]
        parent = [ "." ]
    "#;
    let expected = Policy {
        masks: RulesetMasks {
            fs: AccessFs::from_all(ABI::V6) & !AccessFs::Refer,
            net: AccessNet::from_all(ABI::V6),
            scope: Scope::from_all(ABI::V6),
        },
        ..Policy::new(ABI::V6)
    };

    assert_eq!(parse_json(json).unwrap(), expected);
    assert_eq!(parse_toml(toml).unwrap(), expected);
}

fn assert_schema_valid_empty_ruleset_is_rejected(json: &str) {
    // The schema cannot express aggregate emptiness after ABI clamping and
    // access-group resolution, so this disagreement is intentional.
    assert_eq!(parse_json_schema(json, false), Err(Category::Data));
    assert!(matches!(
        Policy::parse_json(std::io::Cursor::new(json)).unwrap_err(),
        ParseJsonError::Policy(PolicyError::EmptyRuleset)
    ));
}

#[test]
fn test_abi_dependent_empty_ruleset_is_rejected() {
    let v1 = r#"{
        "abi": 1,
        "ruleset": [{
            "unhandledAccessFs": ["abi.all"]
        }]
    }"#;
    let v4 = r#"{
        "abi": 4,
        "ruleset": [{
            "unhandledAccessFs": ["abi.all"]
        }]
    }"#;

    assert_schema_valid_empty_ruleset_is_rejected(v1);
    assert_eq!(
        parse_json(v4).unwrap(),
        Policy {
            masks: RulesetMasks {
                fs: BitFlags::EMPTY,
                net: AccessNet::BindTcp | AccessNet::ConnectTcp,
                scope: BitFlags::EMPTY,
            },
            ..Policy::new(ABI::V4)
        }
    );
}

#[test]
fn test_clamped_future_abi_empty_ruleset_is_rejected() {
    let json = format!(
        r#"{{
            "abi": {},
            "ruleset": [{{
                "unhandledAccessFs": [
                    "execute", "write_file", "read_file", "read_dir",
                    "remove_dir", "remove_file", "make_char", "make_dir",
                    "make_reg", "make_sock", "make_fifo", "make_block",
                    "make_sym", "refer", "truncate", "ioctl_dev"
                ],
                "unhandledAccessNet": ["abi.all"],
                "unscoped": ["abi.all"]
            }}]
        }}"#,
        i32::MAX
    );

    assert_schema_valid_empty_ruleset_is_rejected(&json);
}

#[test]
fn test_all_categories_unhandled_is_rejected() {
    let json = r#"{
        "abi": 6,
        "ruleset": [
            {
                "unhandledAccessFs": [ "abi.all" ],
                "unhandledAccessNet": [ "abi.all" ],
                "unscoped": [ "abi.all" ]
            }
        ]
    }"#;
    let toml = r#"
        abi = 6
        [[ruleset]]
        unhandled_access_fs = [ "abi.all" ]
        unhandled_access_net = [ "abi.all" ]
        unscoped = [ "abi.all" ]
    "#;

    assert_schema_valid_empty_ruleset_is_rejected(json);
    assert!(matches!(
        Policy::parse_toml(toml).unwrap_err(),
        ParseTomlError::Policy(PolicyError::EmptyRuleset)
    ));
}

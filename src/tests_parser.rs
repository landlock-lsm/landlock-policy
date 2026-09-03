// SPDX-License-Identifier: Apache-2.0 OR MIT

use crate::parser::LATEST_ABI;
use crate::policy::{ResolvedPolicy, RulesetMasks};
use crate::tests_helpers::{
    parse_json, parse_json_schema, parse_toml, resolved_policy_with_abi_defaults, validate_json,
};
use crate::Policy;
use landlock::{Access, AccessFs, AccessNet, Scope, ABI};
use serde_json::error::Category;
use std::{collections::BTreeSet, path::PathBuf};

#[test]
fn test_json_schema() {
    let test_json = r#"{
        "abi": 6,
        "ruleset": 0
    }"#;

    validate_json(test_json).expect_err("JSON schema validator should return a type error")
}

#[test]
fn test_embedded_json_schema() {
    let schema_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("schema/landlock-policy.json");
    assert_eq!(
        crate::JSON_SCHEMA,
        std::fs::read_to_string(schema_path).unwrap()
    );
}

/* Test mandatory ABI and optional ruleset normalization. */

#[test]
fn test_empty_policy_json_1() {
    let json = r#"{
    }"#;
    assert_eq!(parse_json(json), Err(Category::Data));
}

#[test]
fn test_null_ruleset_parser_identity() {
    let json = r#"{
        "abi": 6,
        "ruleset": null
    }"#;
    assert_eq!(parse_json_schema(json, false), Ok(Policy::new(ABI::V6)));
}

#[test]
fn test_empty_policy_toml() {
    let toml = "";
    assert!(parse_toml(toml).is_err());
}

/* Test "invalid length 0, expected at least one element" error. */

#[test]
fn test_empty_ruleset_array_json() {
    let json = r#"{
        "abi": 6,
        "ruleset": [ ]
    }"#;
    assert_eq!(parse_json(json), Err(Category::Data));
}

#[test]
fn test_empty_unhandled_access_fs_1() {
    let json = r#"{
        "abi": 6,
        "ruleset": [
            {
                "unhandledAccessFs": [ ]
            }
        ]
    }"#;
    assert_eq!(parse_json(json), Ok(Policy::new(ABI::V6)));
}

#[test]
fn test_empty_unhandled_access_fs_2() {
    let json = r#"{
        "abi": 6,
        "ruleset": [
            {
                "unhandledAccessFs": [ ]
            },
            {
                "unhandledAccessFs": [ "execute" ]
            },
            {
                "unhandledAccessFs": [ ]
            }
        ]
    }"#;
    assert_eq!(
        parse_json(json),
        Ok(Policy {
            masks: RulesetMasks {
                fs: AccessFs::from_all(ABI::V6) & !AccessFs::Execute,
                net: AccessNet::from_all(ABI::V6),
                scope: Scope::from_all(ABI::V6),
            },
            ..Policy::new(ABI::V6)
        })
    );
}

#[test]
fn test_empty_unhandled_access_net() {
    let json = r#"{
        "abi": 6,
        "ruleset": [
            {
                "unhandledAccessNet": [ ]
            }
        ]
    }"#;
    assert_eq!(parse_json(json), Ok(Policy::new(ABI::V6)));
}

#[test]
fn test_empty_scoped() {
    let json = r#"{
        "abi": 6,
        "ruleset": [
            {
                "unscoped": [ ]
            }
        ]
    }"#;
    assert_eq!(parse_json(json), Ok(Policy::new(ABI::V6)));
}

#[test]
fn test_empty_path_beneath() {
    let json = r#"{
        "abi": 6,
        "pathBeneath": [ ]
    }"#;
    assert_eq!(parse_json(json), Err(Category::Data));
}

#[test]
fn test_empty_path_beneath_access() {
    let json = r#"{
        "abi": 6,
        "pathBeneath": [
            {
                "allowedAccess": [ ],
                "parent": [ "." ]
            }
        ]
    }"#;
    assert_eq!(parse_json(json), Err(Category::Data));
}

#[test]
fn test_empty_path_beneath_parent() {
    let json = r#"{
        "abi": 6,
        "pathBeneath": [
            {
                "allowedAccess": [ "execute" ],
                "parent": [ ]
            }
        ]
    }"#;
    assert_eq!(parse_json(json), Err(Category::Data));
}

#[test]
fn test_empty_net_port() {
    let json = r#"{
        "abi": 6,
        "netPort": [ ]
    }"#;
    assert_eq!(parse_json(json), Err(Category::Data));
}

#[test]
fn test_empty_net_port_access() {
    let json = r#"{
        "abi": 6,
        "netPort": [
            {
                "allowedAccess": [ ],
                "port": [ 443 ]
            }
        ]
    }"#;
    assert_eq!(parse_json(json), Err(Category::Data));
}

#[test]
fn test_empty_net_port_number() {
    let json = r#"{
        "abi": 6,
        "netPort": [
            {
                "allowedAccess": [ "bind_tcp" ],
                "port": [ ]
            }
        ]
    }"#;
    assert_eq!(parse_json(json), Err(Category::Data));
}

/* Test "empty ruleset" error. */

#[test]
fn test_empty_ruleset_json() {
    let json = r#"{
        "abi": 6,
        "ruleset": [
            {}
        ]
    }"#;
    assert_eq!(parse_json(json), Ok(Policy::new(ABI::V6)));
}

#[test]
fn test_empty_ruleset_toml() {
    let toml = r#"
        abi = 6
        [[ruleset]]
    "#;
    assert_eq!(parse_toml(toml).unwrap(), Policy::new(ABI::V6));
}

/* Test full ruleset. */

#[test]
fn test_full_ruleset_1() {
    let json = r#"{
        "abi": 6,
        "ruleset": [
            {
                "unhandledAccessFs": [ "execute" ],
                "unhandledAccessNet": [ "bind_tcp" ],
                "unscoped": [ "abstract_unix_socket" ]
            }
        ]
    }"#;
    assert_eq!(
        parse_json(json),
        Ok(Policy {
            masks: RulesetMasks {
                fs: AccessFs::from_all(ABI::V6) & !AccessFs::Execute,
                net: AccessNet::ConnectTcp.into(),
                scope: Scope::Signal.into(),
            },
            ..Policy::new(ABI::V6)
        })
    );
}

#[test]
fn test_full_ruleset_2() {
    let json = r#"{
        "abi": 6,
        "ruleset": [
            {
                "unhandledAccessNet": [ "bind_tcp" ],
                "unscoped": [ "abstract_unix_socket" ],
                "unhandledAccessFs": [ "execute" ]
            }
        ]
    }"#;
    assert_eq!(
        parse_json(json),
        Ok(Policy {
            masks: RulesetMasks {
                fs: AccessFs::from_all(ABI::V6) & !AccessFs::Execute,
                net: AccessNet::ConnectTcp.into(),
                scope: Scope::Signal.into(),
            },
            ..Policy::new(ABI::V6)
        })
    );
}

/* Test ruleset's unhandledAccessFs. */

#[test]
fn test_one_unhandled_access_fs() {
    let json = r#"{
        "abi": 6,
        "ruleset": [
            {
                "unhandledAccessFs": [ "execute" ]
            }
        ]
    }"#;
    assert_eq!(
        parse_json(json),
        Ok(Policy {
            masks: RulesetMasks {
                fs: AccessFs::from_all(ABI::V6) & !AccessFs::Execute,
                net: AccessNet::from_all(ABI::V6),
                scope: Scope::from_all(ABI::V6),
            },
            ..Policy::new(ABI::V6)
        }),
    );
}

#[test]
fn test_all_unhandled_access_fs_json() {
    let json = format!(
        r#"{{
            "abi": {},
            "ruleset": [
                {{
                    "unhandledAccessFs": [
                        "abi.all",
                        "abi.read_execute",
                        "abi.read_write",
                        "execute",
                        "write_file",
                        "read_file",
                        "read_dir",
                        "remove_dir",
                        "remove_file",
                        "make_char",
                        "make_dir",
                        "make_reg",
                        "make_sock",
                        "make_fifo",
                        "make_block",
                        "make_sym",
                        "refer",
                        "truncate",
                        "ioctl_dev"
                        ]
                }}
            ]
        }}"#,
        LATEST_ABI as u32
    );
    assert_eq!(
        parse_json(&json),
        Ok(Policy {
            masks: RulesetMasks {
                fs: Default::default(),
                net: AccessNet::from_all(LATEST_ABI),
                scope: Scope::from_all(LATEST_ABI),
            },
            ..Policy::new(LATEST_ABI)
        })
    );
}

#[test]
fn test_all_unhandled_access_fs_toml() {
    let toml = format!(
        r#"
        abi = {}
        [[ruleset]]
        unhandled_access_fs = [
            "abi.all",
            "abi.read_execute",
            "abi.read_write",
            "execute",
            "write_file",
            "read_file",
            "read_dir",
            "remove_dir",
            "remove_file",
            "make_char",
            "make_dir",
            "make_reg",
            "make_sock",
            "make_fifo",
            "make_block",
            "make_sym",
            "refer",
            "truncate",
            "ioctl_dev",
        ]
        "#,
        LATEST_ABI as u32
    );
    assert_eq!(
        parse_toml(&toml).unwrap(),
        Policy {
            masks: RulesetMasks {
                fs: Default::default(),
                net: AccessNet::from_all(LATEST_ABI),
                scope: Scope::from_all(LATEST_ABI),
            },
            ..Policy::new(LATEST_ABI)
        }
    );
}

#[test]
fn test_unknown_ruleset_field() {
    let json = r#"{
        "abi": 6,
        "ruleset": [
            {
                "unhandledAccessFs": [ "execute" ]
            }
        ],
        "foo": [ ]
    }"#;
    assert_eq!(parse_json(json), Err(Category::Data),);
}

#[test]
fn test_dup_unhandled_access_fs_1() {
    let json = r#"{
        "abi": 6,
        "ruleset": [
            {
                "unhandledAccessFs": [ "execute", "write_file", "execute" ]
            }
        ]
    }"#;
    assert_eq!(
        parse_json(json),
        Ok(Policy {
            masks: RulesetMasks {
                fs: AccessFs::from_all(ABI::V6) & !(AccessFs::Execute | AccessFs::WriteFile),
                net: AccessNet::from_all(ABI::V6),
                scope: Scope::from_all(ABI::V6),
            },
            ..Policy::new(ABI::V6)
        }),
    );
}

#[test]
fn test_dup_unhandled_access_fs_2() {
    let json = r#"{
        "abi": 6,
        "ruleset": [
            {
                "unhandledAccessFs": [ "write_file" ]
            },
            {
                "unhandledAccessFs": [ "execute" ]
            },
            {
                "unhandledAccessFs": [ "write_file" ]
            }
        ]
    }"#;
    assert_eq!(
        parse_json(json),
        Ok(Policy {
            masks: RulesetMasks {
                fs: AccessFs::from_all(ABI::V6) & !(AccessFs::Execute | AccessFs::WriteFile),
                net: AccessNet::from_all(ABI::V6),
                scope: Scope::from_all(ABI::V6),
            },
            ..Policy::new(ABI::V6)
        }),
    );
}

#[test]
fn test_unknown_unhandled_access_fs_1() {
    let json = r#"{
        "abi": 6,
        "ruleset": [
            {
                "unhandledAccessFs": [ "foo" ]
            }
        ]
    }"#;
    assert_eq!(parse_json(json), Err(Category::Data));
}

#[test]
fn test_unknown_unhandled_access_fs_2() {
    let json = r#"{
        "abi": 6,
        "ruleset": [
            {
                "unhandledAccessFs": [ "bind_tcp" ]
            }
        ]
    }"#;
    assert_eq!(parse_json(json), Err(Category::Data));
}

#[test]
fn test_one_path_beneath_str() {
    let json = r#"{
        "abi": 6,
        "pathBeneath": [
            {
                "allowedAccess": [ "execute" ],
                "parent": [ "." ]
            }
        ]
    }"#;
    assert_eq!(
        parse_json(json).unwrap().resolve(),
        Ok(ResolvedPolicy {
            rules_path_beneath: [(PathBuf::from("."), AccessFs::Execute.into())].into(),
            ..resolved_policy_with_abi_defaults(ABI::V6)
        }),
    );
}

#[test]
fn test_one_path_beneath_int() {
    let json = r#"{
        "abi": 6,
        "pathBeneath": [
            {
                "allowedAccess": [ "execute" ],
                "parent": [ 2 ]
            }
        ]
    }"#;
    assert_eq!(parse_json(json), Err(Category::Data));
}

#[test]
fn test_dup_path_beneath_1() {
    let json = r#"{
        "abi": 6,
        "pathBeneath": [
            {
                "allowedAccess": [ "execute" ],
                "parent": [ ".", "." ]
            }
        ]
    }"#;
    assert_eq!(
        parse_json(json).unwrap().resolve(),
        Ok(ResolvedPolicy {
            rules_path_beneath: [(PathBuf::from("."), AccessFs::Execute.into())].into(),
            ..resolved_policy_with_abi_defaults(ABI::V6)
        }),
    );
}

#[test]
fn test_dup_path_beneath_2() {
    let json = r#"{
        "abi": 6,
        "pathBeneath": [
            {
                "allowedAccess": [ "execute" ],
                "parent": [ "." ]
            },
            {
                "allowedAccess": [ "execute" ],
                "parent": [ "." ]
            }
        ]
    }"#;
    assert_eq!(
        parse_json(json).unwrap().resolve(),
        Ok(ResolvedPolicy {
            rules_path_beneath: [(PathBuf::from("."), AccessFs::Execute.into())].into(),
            ..resolved_policy_with_abi_defaults(ABI::V6)
        }),
    );
}

#[test]
fn test_overlap_path_beneath() {
    let json = r#"{
        "abi": 6,
        "pathBeneath": [
            {
                "allowedAccess": [ "execute" ],
                "parent": [ "." ]
            },
            {
                "allowedAccess": [ "write_file" ],
                "parent": [ "." ]
            },
            {
                "allowedAccess": [ "execute", "read_file" ],
                "parent": [ "." ]
            },
            {
                "allowedAccess": [ "execute" ],
                "parent": [ "." ]
            }
        ]
    }"#;
    assert_eq!(
        parse_json(json).unwrap().resolve(),
        Ok(ResolvedPolicy {
            rules_path_beneath: [(
                PathBuf::from("."),
                AccessFs::Execute | AccessFs::ReadFile | AccessFs::WriteFile
            )]
            .into(),
            ..resolved_policy_with_abi_defaults(ABI::V6)
        }),
    );
}

#[test]
fn test_normalization_path_beneath() {
    let json = r#"{
        "abi": 6,
        "pathBeneath": [
            {
                "allowedAccess": [ "execute" ],
                "parent": [ ".", "./", ".", "a/./b" ]
            },
            {
                "allowedAccess": [ "execute" ],
                "parent": [ ".//", "a/////b", "c/../c" ]
            }
        ]
    }"#;
    assert_eq!(
        parse_json(json).unwrap().resolve(),
        Ok(ResolvedPolicy {
            rules_path_beneath: [
                (PathBuf::from("."), AccessFs::Execute.into()),
                (PathBuf::from("a/b"), AccessFs::Execute.into()),
                (PathBuf::from("c/../c"), AccessFs::Execute.into()),
            ]
            .into(),
            ..resolved_policy_with_abi_defaults(ABI::V6)
        }),
    );
}

/* Test ruleset's unhandledAccessNet. */

#[test]
fn test_one_unhandled_access_net() {
    let json = r#"{
        "abi": 6,
        "ruleset": [
            {
                "unhandledAccessNet": [ "bind_tcp" ]
            }
        ]
    }"#;
    assert_eq!(
        parse_json(json),
        Ok(Policy {
            masks: RulesetMasks {
                fs: AccessFs::from_all(ABI::V6),
                net: AccessNet::ConnectTcp.into(),
                scope: Scope::from_all(ABI::V6),
            },
            ..Policy::new(ABI::V6)
        }),
    );
}

#[test]
fn test_all_unhandled_access_net() {
    let json = r#"{
        "abi": 6,
        "ruleset": [
            {
                "unhandledAccessNet": [
                    "bind_tcp",
                    "connect_tcp",
                    "abi.all"
                    ]
            }
        ]
    }"#;
    assert_eq!(
        parse_json(json),
        Ok(Policy {
            masks: RulesetMasks {
                fs: AccessFs::from_all(ABI::V6),
                net: Default::default(),
                scope: Scope::from_all(ABI::V6),
            },
            ..Policy::new(ABI::V6)
        }),
    );
}

#[test]
fn test_dup_unhandled_access_net_1() {
    let json = r#"{
        "abi": 6,
        "ruleset": [
            {
                "unhandledAccessNet": [ "bind_tcp", "connect_tcp", "bind_tcp" ]
            }
        ]
    }"#;
    assert_eq!(
        parse_json(json),
        Ok(Policy {
            masks: RulesetMasks {
                fs: AccessFs::from_all(ABI::V6),
                net: Default::default(),
                scope: Scope::from_all(ABI::V6),
            },
            ..Policy::new(ABI::V6)
        }),
    );
}

#[test]
fn test_dup_unhandled_access_net_2() {
    let json = r#"{
        "abi": 6,
        "ruleset": [
            {
                "unhandledAccessNet": [ "connect_tcp" ]
            },
            {
                "unhandledAccessNet": [ "bind_tcp" ]
            },
            {
                "unhandledAccessNet": [ "connect_tcp" ]
            }
        ]
    }"#;
    assert_eq!(
        parse_json(json),
        Ok(Policy {
            masks: RulesetMasks {
                fs: AccessFs::from_all(ABI::V6),
                net: Default::default(),
                scope: Scope::from_all(ABI::V6),
            },
            ..Policy::new(ABI::V6)
        }),
    );
}

#[test]
fn test_unknown_unhandled_access_net_1() {
    let json = r#"{
        "abi": 6,
        "ruleset": [
            {
                "unhandledAccessNet": [ "foo" ]
            }
        ]
    }"#;
    assert_eq!(parse_json(json), Err(Category::Data));
}

#[test]
fn test_unknown_unhandled_access_net_2() {
    let json = r#"{
        "abi": 6,
        "ruleset": [
            {
                "unhandledAccessNet": [ "execute" ]
            }
        ]
    }"#;
    assert_eq!(parse_json(json), Err(Category::Data));
}

#[test]
fn test_one_net_port() {
    let json = r#"{
        "abi": 6,
        "netPort": [
            {
                "allowedAccess": [ "bind_tcp" ],
                "port": [ 443 ]
            }
        ]
    }"#;
    assert_eq!(
        parse_json(json),
        Ok(Policy {
            rules_net_port: [(443, AccessNet::BindTcp.into())].into(),
            ..Policy::new(ABI::V6)
        }),
    );
}

#[test]
fn test_overlap_net_port() {
    let json = r#"{
        "abi": 6,
        "netPort": [
            {
                "allowedAccess": [ "connect_tcp" ],
                "port": [ 443 ]
            },
            {
                "allowedAccess": [ "bind_tcp" ],
                "port": [ 443 ]
            },
            {
                "allowedAccess": [ "connect_tcp" ],
                "port": [ 443 ]
            }
        ]
    }"#;
    assert_eq!(
        parse_json(json),
        Ok(Policy {
            rules_net_port: [(443, AccessNet::BindTcp | AccessNet::ConnectTcp)].into(),
            ..Policy::new(ABI::V6)
        }),
    );
}

/* Test ruleset's properties. */

#[test]
fn test_mix_unhandled_access_1() {
    let json = r#"{
        "abi": 6,
        "ruleset": [
            {
                "unhandledAccessFs": [ "execute" ],
                "unhandledAccessNet": [ "bind_tcp" ]
            }
        ]
    }"#;
    assert_eq!(
        parse_json(json),
        Ok(Policy {
            masks: RulesetMasks {
                fs: AccessFs::from_all(ABI::V6) & !AccessFs::Execute,
                net: AccessNet::ConnectTcp.into(),
                scope: Scope::from_all(ABI::V6),
            },
            ..Policy::new(ABI::V6)
        })
    );
}

#[test]
fn test_mix_unhandled_access_2() {
    let json = r#"{
        "abi": 6,
        "ruleset": [
            {
                "unhandledAccessFs": [ "execute" ],
                "unhandledAccessNet": [ "bind_tcp" ]
            },
            {
                "unhandledAccessNet": [ "connect_tcp" ]
            }
        ]
    }"#;
    assert_eq!(
        parse_json(json),
        Ok(Policy {
            masks: RulesetMasks {
                fs: AccessFs::from_all(ABI::V6) & !AccessFs::Execute,
                net: Default::default(),
                scope: Scope::from_all(ABI::V6),
            },
            ..Policy::new(ABI::V6)
        })
    );
}

/* Test ruleset's unscoped. */

#[test]
fn test_one_unscoped() {
    let json = r#"{
        "abi": 6,
        "ruleset": [
            {
                "unscoped": [ "abstract_unix_socket" ]
            }
        ]
    }"#;
    assert_eq!(
        parse_json(json),
        Ok(Policy {
            masks: RulesetMasks {
                fs: AccessFs::from_all(ABI::V6),
                net: AccessNet::from_all(ABI::V6),
                scope: Scope::Signal.into(),
            },
            ..Policy::new(ABI::V6)
        }),
    );
}

#[test]
fn test_all_unscoped() {
    let json = r#"{
        "abi": 6,
        "ruleset": [
            {
                "unscoped": [
                    "abstract_unix_socket",
                    "signal",
                    "abi.all"
                    ]
            }
        ]
    }"#;
    assert_eq!(
        parse_json(json),
        Ok(Policy {
            masks: RulesetMasks {
                fs: AccessFs::from_all(ABI::V6),
                net: AccessNet::from_all(ABI::V6),
                scope: Default::default(),
            },
            ..Policy::new(ABI::V6)
        }),
    );
}

#[test]
fn test_dup_unscoped_1() {
    let json = r#"{
        "abi": 6,
        "ruleset": [
            {
                "unscoped": [ "abstract_unix_socket", "signal", "abstract_unix_socket" ]
            }
        ]
    }"#;
    assert_eq!(
        parse_json(json),
        Ok(Policy {
            masks: RulesetMasks {
                fs: AccessFs::from_all(ABI::V6),
                net: AccessNet::from_all(ABI::V6),
                scope: Default::default(),
            },
            ..Policy::new(ABI::V6)
        }),
    );
}

#[test]
fn test_dup_unscoped_2() {
    let json = r#"{
        "abi": 6,
        "ruleset": [
            {
                "unscoped": [ "signal" ]
            },
            {
                "unscoped": [ "abstract_unix_socket" ]
            },
            {
                "unscoped": [ "signal" ]
            }
        ]
    }"#;
    assert_eq!(
        parse_json(json),
        Ok(Policy {
            masks: RulesetMasks {
                fs: AccessFs::from_all(ABI::V6),
                net: AccessNet::from_all(ABI::V6),
                scope: Default::default(),
            },
            ..Policy::new(ABI::V6)
        }),
    );
}

#[test]
fn test_unknown_unscoped_1() {
    let json = r#"{
        "abi": 6,
        "ruleset": [
            {
                "unscoped": [ "foo" ]
            }
        ]
    }"#;
    assert_eq!(parse_json(json), Err(Category::Data));
}

#[test]
fn test_unknown_unscoped_2() {
    let json = r#"{
        "abi": 6,
        "ruleset": [
            {
                "unscoped": [ "execute" ]
            }
        ]
    }"#;
    assert_eq!(parse_json(json), Err(Category::Data));
}

/* Test inference. */

#[test]
fn test_mixed_exclusion_and_rule() {
    let json = r#"{
        "abi": 6,
        "ruleset": [
            {
                "unhandledAccessFs": [ "execute" ]
            }
        ],
        "netPort": [
            {
                "allowedAccess": [ "bind_tcp" ],
                "port": [ 443 ]
            }
        ]
    }"#;
    assert_eq!(
        parse_json(json),
        Ok(Policy {
            masks: RulesetMasks {
                fs: AccessFs::from_all(ABI::V6) & !AccessFs::Execute,
                net: AccessNet::from_all(ABI::V6),
                scope: Scope::from_all(ABI::V6),
            },
            rules_net_port: [(443, AccessNet::BindTcp.into())].into(),
            ..Policy::new(ABI::V6)
        }),
    );
}

#[test]
fn test_rules_do_not_augment_handled_access_fs() {
    let json = r#"{
        "abi": 6,
        "ruleset": [
            {
                "unhandledAccessFs": [ "execute" ]
            }
        ],
        "pathBeneath": [
            {
                "allowedAccess": [ "write_file" ],
                "parent": [ "." ]
            },
            {
                "allowedAccess": [ "read_file" ],
                "parent": [ "." ]
            }
        ]
    }"#;
    assert_eq!(
        parse_json(json).unwrap().resolve(),
        Ok(ResolvedPolicy {
            handled_fs: AccessFs::from_all(ABI::V6) & !AccessFs::Execute,
            rules_path_beneath: [(PathBuf::from("."), AccessFs::WriteFile | AccessFs::ReadFile)]
                .into(),
            ..resolved_policy_with_abi_defaults(ABI::V6)
        })
    );
}

#[test]
fn test_rules_do_not_augment_handled_access_net() {
    let json = r#"{
        "abi": 6,
        "ruleset": [
            {
                "unhandledAccessNet": [ "bind_tcp" ]
            }
        ],
        "netPort": [
            {
                "allowedAccess": [ "connect_tcp" ],
                "port": [ 443 ]
            }
        ]
    }"#;
    assert_eq!(
        parse_json(json),
        Ok(Policy {
            masks: RulesetMasks {
                fs: AccessFs::from_all(ABI::V6),
                net: AccessNet::ConnectTcp.into(),
                scope: Scope::from_all(ABI::V6),
            },
            rules_net_port: [(443, AccessNet::ConnectTcp.into())].into(),
            ..Policy::new(ABI::V6)
        })
    );
}

#[test]
fn test_path_beneath_alone() {
    let json = r#"{
        "abi": 6,
        "pathBeneath": [
            {
                "allowedAccess": [ "execute" ],
                "parent": [ "." ]
            }
        ]
    }"#;
    assert_eq!(
        parse_json(json).unwrap().resolve(),
        Ok(ResolvedPolicy {
            rules_path_beneath: [(PathBuf::from("."), AccessFs::Execute.into())].into(),
            ..resolved_policy_with_abi_defaults(ABI::V6)
        })
    );
}

#[test]
fn test_net_port_alone() {
    let json = r#"{
        "abi": 6,
        "netPort": [
            {
                "allowedAccess": [ "bind_tcp" ],
                "port": [ 443 ]
            }
        ]
    }"#;
    assert_eq!(
        parse_json(json),
        Ok(Policy {
            rules_net_port: [(443, AccessNet::BindTcp.into())].into(),
            ..Policy::new(ABI::V6)
        })
    );
}

#[test]
fn test_examples() {
    let mini_scoped = include_str!("../examples/mini-scoped.json");
    let mini_scoped_policy = parse_json(mini_scoped).unwrap();
    assert!(mini_scoped_policy.masks.fs.is_empty());
    assert!(mini_scoped_policy.masks.net.is_empty());
    assert_eq!(mini_scoped_policy.masks.scope, Scope::from_all(ABI::V6));
    validate_json(mini_scoped).unwrap();

    for json in [
        include_str!("../examples/mini-write-tmp.json"),
        include_str!("../examples/verbose-write-tmp.json"),
    ] {
        parse_json(json).unwrap();
        validate_json(json).unwrap();
    }
    for toml in [
        include_str!("../examples/micro-var.toml"),
        include_str!("../examples/micro-write-tmp.toml"),
        include_str!("../examples/mini-write-tmp.toml"),
    ] {
        parse_toml(toml).unwrap();
    }
}

fn schema_enum_names(definition: &str) -> BTreeSet<String> {
    let schema: serde_json::Value = serde_json::from_str(crate::JSON_SCHEMA).unwrap();
    schema["definitions"][definition]["enum"]
        .as_array()
        .unwrap()
        .iter()
        .map(|name| name.as_str().unwrap().to_owned())
        .collect()
}

#[test]
fn test_all_schema_access_names() {
    for (definition, json_field, toml_field) in [
        ("accessFs", "unhandledAccessFs", "unhandled_access_fs"),
        ("accessNet", "unhandledAccessNet", "unhandled_access_net"),
        ("scope", "unscoped", "unscoped"),
    ] {
        for name in schema_enum_names(definition) {
            let json = format!(
                r#"{{
                    "abi": {},
                    "ruleset": [
                        {{
                            "{json_field}": [ "{name}" ]
                        }}
                    ]
                }}"#,
                LATEST_ABI as i32
            );
            let toml = format!(
                r#"
                    abi = {}
                    [[ruleset]]
                    {toml_field} = [ "{name}" ]
                "#,
                LATEST_ABI as i32
            );
            parse_json(&json).unwrap();
            parse_toml(&toml).unwrap();
        }
    }
}

#[test]
fn test_null_only_ruleset_fragment_is_omitted() {
    let json = r#"{
        "abi": 6,
        "ruleset": [
            {
                "unhandledAccessFs": null
            }
        ]
    }"#;

    assert_eq!(parse_json(json), Ok(Policy::new(ABI::V6)));
    validate_json(json).unwrap();
}

#[test]
fn test_null_inverse_member_is_rejected() {
    let json = r#"{
        "abi": 6,
        "ruleset": [
            {
                "unhandledAccessFs": [ null ]
            }
        ]
    }"#;

    assert!(parse_json(json).is_err());
    assert!(validate_json(json).is_err());
}

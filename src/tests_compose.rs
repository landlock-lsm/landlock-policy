// SPDX-License-Identifier: Apache-2.0 OR MIT

use crate::{
    policy::ResolvedPolicy,
    tests_helpers::{parse_json, resolved_policy_with_abi_defaults},
    BuildRulesetError, Policy,
};
use landlock::{Access, AccessFs, AccessNet, CreateRulesetError, RulesetError, Scope, ABI};
use std::path::PathBuf;

fn test_idempotence(policy: &Policy) {
    let mut bkp = policy.clone();
    bkp.compose(policy);
    assert_eq!(*policy, bkp);
}

fn get_composition(json1: &str, json2: &str) -> ResolvedPolicy {
    let j1 = parse_json(json1).unwrap();
    test_idempotence(&j1);

    let j2 = parse_json(json2).unwrap();
    test_idempotence(&j2);

    let mut c1 = j1.clone();
    c1.compose(&j2);
    test_idempotence(&c1);

    let mut c2 = j2.clone();
    c2.compose(&j1);
    test_idempotence(&c2);

    // Test commutativity
    assert_eq!(c1, c2);

    c1.resolve().unwrap()
}

#[test]
fn test_compose_most_fs_net() {
    let json1 = r#"{
        "abi": 4
    }"#;
    let json2 = r#"{
        "abi": 6,
        "pathBeneath": [
            {
                "allowedAccess": [ "abi.all" ],
                "parent": [ "a" ]
            }
        ],
        "netPort": [
            {
                "allowedAccess": [ "abi.all" ],
                "port": [ 1 ]
            }
        ]
    }"#;

    assert_eq!(
        get_composition(json1, json2),
        ResolvedPolicy {
            rules_path_beneath: [(PathBuf::from("a"), AccessFs::from_all(ABI::V4))].into(),
            rules_net_port: [(1, AccessNet::from_all(ABI::V4))].into(),
            ..resolved_policy_with_abi_defaults(ABI::V4)
        }
    );
}

#[test]
fn test_compose_scope() {
    let json1 = r#"{
        "abi": 6,
        "ruleset": [
            {
                "unscoped": [ "signal" ]
            }
        ]
    }"#;
    let json2 = r#"{
        "abi": 6
    }"#;

    assert_eq!(
        get_composition(json1, json2),
        ResolvedPolicy {
            scoped: Scope::AbstractUnixSocket.into(),
            ..resolved_policy_with_abi_defaults(ABI::V6)
        }
    );
}

#[test]
fn test_compose_allowance_union() {
    let json1 = r#"{
        "abi": 6,
        "pathBeneath": [
            {
                "allowedAccess": [ "execute" ],
                "parent": [ "a" ]
            }
        ]
    }"#;
    let json2 = r#"{
        "abi": 6,
        "pathBeneath": [
            {
                "allowedAccess": [ "read_file" ],
                "parent": [ "a" ]
            },
            {
                "allowedAccess": [ "read_file" ],
                "parent": [ "b" ]
            }
        ]
    }"#;

    assert_eq!(
        get_composition(json1, json2),
        ResolvedPolicy {
            rules_path_beneath: [
                (PathBuf::from("a"), AccessFs::Execute | AccessFs::ReadFile,),
                (PathBuf::from("b"), AccessFs::ReadFile.into()),
            ]
            .into(),
            ..resolved_policy_with_abi_defaults(ABI::V6)
        }
    );
}

#[test]
fn test_composition_can_be_empty() {
    let json1 = r#"{
        "abi": 6,
        "ruleset": [
            {
                "unhandledAccessNet": [ "abi.all" ],
                "unscoped": [ "abi.all" ]
            }
        ]
    }"#;
    let json2 = r#"{
        "abi": 6,
        "ruleset": [
            {
                "unhandledAccessFs": [ "abi.all" ],
                "unscoped": [ "abi.all" ]
            }
        ]
    }"#;

    let resolved = get_composition(json1, json2);
    assert_eq!(resolved, ResolvedPolicy::default());
    assert!(matches!(
        resolved.build_ruleset(),
        Err(BuildRulesetError::Ruleset(RulesetError::CreateRuleset(
            CreateRulesetError::MissingHandledAccess
        )))
    ));
}

#[test]
fn test_compose_complement1() {
    let json1 = r#"{
        "abi": 6,
        "ruleset": [
            {
                "unhandledAccessFs": [ "execute" ]
            }
        ]
    }"#;
    let json2 = r#"{
        "abi": 6,
        "pathBeneath": [
            {
                "allowedAccess": [ "execute", "read_file" ],
                "parent": [ "a" ]
            },
            {
                "allowedAccess": [ "read_file" ],
                "parent": [ "b" ]
            }
        ]
    }"#;

    assert_eq!(
        get_composition(json1, json2),
        ResolvedPolicy {
            handled_fs: AccessFs::from_all(ABI::V6) & !AccessFs::Execute,
            rules_path_beneath: [
                (PathBuf::from("a"), AccessFs::ReadFile.into()),
                (PathBuf::from("b"), AccessFs::ReadFile.into()),
            ]
            .into(),
            ..resolved_policy_with_abi_defaults(ABI::V6)
        }
    );
}

#[test]
fn test_compose_complement2() {
    let json1 = r#"{
        "abi": 6,
        "pathBeneath": [
            {
                "allowedAccess": [ "execute", "read_file" ],
                "parent": [ "a" ]
            },
            {
                "allowedAccess": [ "read_file" ],
                "parent": [ "b" ]
            }
        ]
    }"#;
    let json2 = r#"{
        "abi": 6,
        "ruleset": [
            {
                "unhandledAccessFs": [ "read_file" ]
            }
        ]
    }"#;

    assert_eq!(
        get_composition(json1, json2),
        ResolvedPolicy {
            handled_fs: AccessFs::from_all(ABI::V6) & !AccessFs::ReadFile,
            rules_path_beneath: [(PathBuf::from("a"), AccessFs::Execute.into()),].into(),
            ..resolved_policy_with_abi_defaults(ABI::V6)
        }
    );
}

#[test]
fn test_compose_standalone_variable() {
    let json1 = r#"{
        "abi": 6,
        "variable": [
            {
                "name": "foo",
                "literal": [ "a", "b" ]
            }
        ],
        "pathBeneath": [
            {
                "allowedAccess": [ "execute" ],
                "parent": [ "${foo}" ]
            }
        ]
    }"#;
    let json2 = r#"{
        "abi": 6,
        "pathBeneath": [
            {
                "allowedAccess": [ "read_file" ],
                "parent": [ "a", "b" ]
            }
        ]
    }"#;

    assert_eq!(
        get_composition(json1, json2),
        ResolvedPolicy {
            rules_path_beneath: [
                (PathBuf::from("a"), AccessFs::Execute | AccessFs::ReadFile),
                (PathBuf::from("b"), AccessFs::Execute | AccessFs::ReadFile),
            ]
            .into(),
            ..resolved_policy_with_abi_defaults(ABI::V6)
        }
    );
}

#[test]
fn test_compose_shared_variable() {
    let json1 = r#"{
        "abi": 6,
        "variable": [
            {
                "name": "foo",
                "literal": [ "a", "b" ]
            }
        ],
        "pathBeneath": [
            {
                "allowedAccess": [ "execute" ],
                "parent": [ "${foo}" ]
            }
        ]
    }"#;
    let json2 = r#"{
        "abi": 6,
        "variable": [
            {
                "name": "foo"
            }
        ],
        "pathBeneath": [
            {
                "allowedAccess": [ "read_file" ],
                "parent": [ "${foo}" ]
            },
            {
                "allowedAccess": [ "read_file" ],
                "parent": [ "x/${foo}" ]
            }
        ]
    }"#;

    assert_eq!(
        get_composition(json1, json2),
        ResolvedPolicy {
            rules_path_beneath: [
                (PathBuf::from("a"), AccessFs::Execute | AccessFs::ReadFile),
                (PathBuf::from("b"), AccessFs::Execute | AccessFs::ReadFile),
                (PathBuf::from("x/a"), AccessFs::ReadFile.into()),
                (PathBuf::from("x/b"), AccessFs::ReadFile.into()),
            ]
            .into(),
            ..resolved_policy_with_abi_defaults(ABI::V6)
        }
    );
}

#[test]
fn test_compose_same_resolved_path() {
    let json1 = r#"{
        "abi": 6,
        "variable": [
            {
                "name": "foo",
                "literal": [ "a" ]
            }
        ],
        "pathBeneath": [
            {
                "allowedAccess": [ "execute" ],
                "parent": [ "${foo}" ]
            }
        ]
    }"#;
    let json2 = r#"{
        "abi": 6,
        "variable": [
            {
                "name": "bar",
                "literal": [ "a" ]
            }
        ],
        "pathBeneath": [
            {
                "allowedAccess": [ "read_file" ],
                "parent": [ "${bar}" ]
            }
        ]
    }"#;

    assert_eq!(
        get_composition(json1, json2),
        ResolvedPolicy {
            rules_path_beneath: [(PathBuf::from("a"), AccessFs::Execute | AccessFs::ReadFile)]
                .into(),
            ..resolved_policy_with_abi_defaults(ABI::V6)
        }
    );
}

// Test with composition of two different ABIs (different than user variables,
// see TryFrom<Policy> for ResolvedPolicy).
#[test]
fn test_abi_compose_all() {
    let json1 = r#"{
        "abi": 1,
        "pathBeneath": [
            {
                "allowedAccess": [ "abi.read_execute" ],
                "parent": [ "." ]
            }
        ],
        "netPort": [
            {
                "allowedAccess": [ "abi.all" ],
                "port": [ 1 ]
            }
        ]
    }"#;
    let json2 = r#"{
        "abi": 2,
        "pathBeneath": [
            {
                "allowedAccess": [ "abi.read_write" ],
                "parent": [ "." ]
            }
        ],
        "netPort": [
            {
                "allowedAccess": [ "abi.all" ],
                "port": [ 1 ]
            }
        ]
    }"#;

    assert_eq!(
        get_composition(json1, json2),
        ResolvedPolicy {
            rules_path_beneath: [(PathBuf::from("."), AccessFs::from_all(ABI::V1))].into(),
            ..resolved_policy_with_abi_defaults(ABI::V1)
        }
    );
}

#[test]
fn test_abi_compose_read_write_v1() {
    let json1 = r#"{
        "abi": 1,
        "pathBeneath": [
            {
                "allowedAccess": [ "abi.read_execute" ],
                "parent": [ "." ]
            }
        ]
    }"#;
    let json2 = r#"{
        "abi": 4,
        "ruleset": [
            {
                "unhandledAccessFs": [ "execute" ]
            }
        ],
        "pathBeneath": [
            {
                "allowedAccess": [ "abi.read_write" ],
                "parent": [ "." ]
            }
        ],
        "netPort": [
            {
                "allowedAccess": [ "abi.all" ],
                "port": [ 1 ]
            }
        ]
    }"#;

    assert_eq!(
        get_composition(json1, json2),
        ResolvedPolicy {
            handled_fs: AccessFs::from_all(ABI::V1) & !AccessFs::Execute,
            rules_path_beneath: [(
                PathBuf::from("."),
                AccessFs::from_all(ABI::V1) & !AccessFs::Execute
            )]
            .into(),
            ..resolved_policy_with_abi_defaults(ABI::V1)
        }
    );
}

#[test]
fn test_abi_compose_read_write_v4() {
    let json1 = r#"{
        "abi": 4,
        "pathBeneath": [
            {
                "allowedAccess": [ "abi.read_execute" ],
                "parent": [ "." ]
            }
        ],
        "netPort": [
            {
                "allowedAccess": [ "abi.all" ],
                "port": [ 1 ]
            }
        ]
    }"#;
    let json2 = r#"{
        "abi": 6,
        "ruleset": [
            {
                "unhandledAccessFs": [ "execute" ],
                "unhandledAccessNet": [ "connect_tcp" ]
            }
        ],
        "pathBeneath": [
            {
                "allowedAccess": [ "abi.read_write" ],
                "parent": [ "." ]
            }
        ],
        "netPort": [
            {
                "allowedAccess": [ "abi.all" ],
                "port": [ 1 ]
            }
        ]
    }"#;

    assert_eq!(
        get_composition(json1, json2),
        ResolvedPolicy {
            handled_fs: AccessFs::from_all(ABI::V4) & !AccessFs::Execute,
            handled_net: AccessNet::BindTcp.into(),
            rules_path_beneath: [(
                PathBuf::from("."),
                AccessFs::from_all(ABI::V4) & !AccessFs::Execute
            )]
            .into(),
            rules_net_port: [(1, AccessNet::BindTcp.into())].into(),
            ..resolved_policy_with_abi_defaults(ABI::V4)
        }
    );
}

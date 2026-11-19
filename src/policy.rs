// SPDX-License-Identifier: Apache-2.0 OR MIT

use crate::nonempty::NonEmptyStruct;
use crate::parser::{JsonPolicy, JsonRuleset, TemplateString, TomlPolicy};
use crate::variable::{NameError, ResolveError, Variables, VecStringIterator};
use landlock::{
    AccessFs, AccessNet, BitFlags, NetPort, PathBeneath, PathFd, PathFdError, Ruleset, RulesetAttr,
    RulesetCreated, RulesetCreatedAttr, RulesetError, Scope, ABI,
};
use std::collections::BTreeMap;
use std::fs::{self, File};
use std::num::TryFromIntError;
use std::ops::{BitAnd, BitOr};
use std::path::{Path, PathBuf};
use thiserror::Error;

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum BuildRulesetError {
    #[error(transparent)]
    PathFd(#[from] PathFdError),
    #[error(transparent)]
    Integer(#[from] TryFromIntError),
    #[error(transparent)]
    Ruleset(#[from] RulesetError),
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct RulesetMasks {
    pub(crate) fs: BitFlags<AccessFs>,
    pub(crate) net: BitFlags<AccessNet>,
    pub(crate) scope: BitFlags<Scope>,
}

impl BitOr for RulesetMasks {
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self::Output {
        Self {
            fs: self.fs | rhs.fs,
            net: self.net | rhs.net,
            scope: self.scope | rhs.scope,
        }
    }
}

impl BitAnd for RulesetMasks {
    type Output = Self;

    fn bitand(self, rhs: Self) -> Self::Output {
        Self {
            fs: self.fs & rhs.fs,
            net: self.net & rhs.net,
            scope: self.scope & rhs.scope,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Policy {
    /// Effective ABI used to interpret every listed access right.
    pub(crate) abi: ABI,
    pub(crate) variables: Variables,
    pub(crate) masks: RulesetMasks,
    pub(crate) rules_path_beneath: BTreeMap<TemplateString, BitFlags<AccessFs>>,
    pub(crate) rules_net_port: BTreeMap<u64, BitFlags<AccessNet>>,
}

#[cfg_attr(test, derive(Default))]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResolvedPolicy {
    pub(crate) handled_fs: BitFlags<AccessFs>,
    pub(crate) handled_net: BitFlags<AccessNet>,
    pub(crate) scoped: BitFlags<Scope>,
    // Thanks to the BTreeMap:
    // * the paths are unique, which guarantee that allowed access are only set once for each path;
    // * the paths are sorted (the longest path is the last one), which makes policies deterministic and idempotent.
    // Thanks to PathBuf, paths are normalized.
    pub(crate) rules_path_beneath: BTreeMap<PathBuf, BitFlags<AccessFs>>,
    pub(crate) rules_net_port: BTreeMap<u64, BitFlags<AccessNet>>,
}

#[derive(Debug, Error)]
pub enum PolicyError {
    #[error(transparent)]
    Name(#[from] NameError),
    #[error(transparent)]
    Resolve(#[from] ResolveError),
}

impl TryFrom<NonEmptyStruct<JsonPolicy>> for Policy {
    type Error = PolicyError;

    fn try_from(json: NonEmptyStruct<JsonPolicy>) -> Result<Self, Self::Error> {
        let json = json.into_inner();
        let mut policy = Self::empty(json.abi.into());

        for variable in json.variable.unwrap_or_default() {
            let name = variable.name.parse()?;
            let literal = variable.literal.unwrap_or_default();
            // TODO: Check and warn if users tried to use variable in literal strings?
            policy.variables.extend(name, literal);
        }

        for ruleset in json.ruleset.unwrap_or_default() {
            let JsonRuleset {
                handledAccessFs,
                handledAccessNet,
                scoped,
            } = ruleset.into_inner();
            policy.masks = policy.masks
                | RulesetMasks {
                    fs: handledAccessFs
                        .map(|access| access.resolve_bitflags(policy.abi))
                        .unwrap_or_default(),
                    net: handledAccessNet
                        .map(|access| access.resolve_bitflags(policy.abi))
                        .unwrap_or_default(),
                    scope: scoped
                        .map(|scoped| scoped.resolve_bitflags(policy.abi))
                        .unwrap_or_default(),
                };
        }

        for path_beneath in json.pathBeneath.unwrap_or_default() {
            let access = path_beneath.allowedAccess.resolve_bitflags(policy.abi);

            // It is possible to have rules with empty access because of empty
            // access group resolution.
            if !access.is_empty() {
                // Automatically augment and keep the ruleset consistent.
                policy.masks.fs |= access;

                for parent in path_beneath.parent {
                    policy
                        .rules_path_beneath
                        .entry(parent)
                        .and_modify(|a| *a |= access)
                        .or_insert(access);
                }
            }
        }

        for net_port in json.netPort.unwrap_or_default() {
            let access = net_port.allowedAccess.resolve_bitflags(policy.abi);

            // It is possible to have rules with empty access because of empty
            // access group resolution.
            if !access.is_empty() {
                // Automatically augment and keep the ruleset consistent.
                policy.masks.net |= access;

                for port in net_port.port {
                    policy
                        .rules_net_port
                        .entry(port)
                        .and_modify(|a| *a |= access)
                        .or_insert(access);
                }
            }
        }

        Ok(policy)
    }
}

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum RuleError {
    #[error(transparent)]
    PathFd(#[from] PathFdError),
}

#[derive(Debug, Error)]
pub enum ParseJsonError {
    #[error(transparent)]
    Policy(#[from] PolicyError),
    #[error(transparent)]
    SerdeJson(#[from] serde_json::Error),
}

#[cfg(feature = "toml")]
#[derive(Debug, Error)]
pub enum ParseTomlError {
    #[error(transparent)]
    Policy(#[from] PolicyError),
    #[error(transparent)]
    SerdeToml(#[from] toml::de::Error),
}

#[derive(Debug, Error)]
pub enum ParseFileError {
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    ParseJson(#[from] ParseJsonError),
    #[cfg(feature = "toml")]
    #[error(transparent)]
    ParseToml(#[from] ParseTomlError),
}

fn format_parse_files_error(errors: &BTreeMap<PathBuf, ParseFileError>) -> String {
    errors
        .iter()
        .map(|(path, error)| format!("{}: {}", path.display(), error))
        .collect::<Vec<_>>()
        .join("\n")
}

#[derive(Debug, Error)]
pub enum ParseDirectoryError {
    #[error(transparent)]
    Io(#[from] std::io::Error),
    // Use BTreeMap for deterministic errors.
    #[error("failed to parse policy file(s):\n\n{}", format_parse_files_error(.0))]
    ParseFiles(BTreeMap<PathBuf, ParseFileError>),
    #[error("no policy file found")]
    NoPolicyFile,
}

impl From<ParseDirectoryError> for std::io::Error {
    fn from(err: ParseDirectoryError) -> Self {
        match err {
            ParseDirectoryError::Io(err) => err,
            ParseDirectoryError::ParseFiles(_) => {
                std::io::Error::new(std::io::ErrorKind::InvalidData, err)
            }
            ParseDirectoryError::NoPolicyFile => {
                std::io::Error::new(std::io::ErrorKind::NotFound, err)
            }
        }
    }
}

pub enum PolicyFormat {
    Json,
    #[cfg(feature = "toml")]
    Toml,
}

impl PolicyFormat {
    fn extension(&self) -> &'static str {
        match self {
            PolicyFormat::Json => "json",
            #[cfg(feature = "toml")]
            PolicyFormat::Toml => "toml",
        }
    }
}

impl Policy {
    // Policy cannot implement Default because every policy requires an
    // explicit ABI.
    pub(crate) fn empty(abi: ABI) -> Self {
        Self {
            abi,
            variables: Default::default(),
            masks: Default::default(),
            rules_path_beneath: Default::default(),
            rules_net_port: Default::default(),
        }
    }

    /// Composes two policies by merging `other` with `self` in a safe
    /// best-effort way, which means the common handled access rights with all
    /// rules.
    ///
    /// When both policies declare different ABI versions (e.g., one against
    /// ABI::V1 and another against ABI::V2), the composition retains the lower
    /// version. Handled access rights are independently intersected.
    ///
    /// # Behavior
    ///
    /// - Handled access rights are combined using bitwise AND (intersection).
    /// - Scoped rights are combined using bitwise AND (intersection).
    /// - Rules are merged with access rights limited to commonly handled ones.
    /// - Paths and ports with empty access rights after intersection are removed.
    /// - Variables from both policies are merged.
    /// - If both policies declare ABI versions, the lower version is retained.
    ///
    /// # Commutativity
    ///
    /// This operation is commutative: `a.compose(&b)` produces the same result
    /// as `b.compose(&a)`. The order of composition does not affect the final
    /// policy, ensuring predictable behavior regardless of the sequence
    /// in which policies are combined.
    pub fn compose(&mut self, other: &Self) {
        let common_masks = self.masks & other.masks;
        let common_handled_fs = common_masks.fs;
        let common_handled_net = common_masks.net;

        // First step: downgrade the current access rights according to other's
        // handled access rights, and remove entries with empty accesses.
        self.rules_path_beneath.retain(|_, access| {
            *access &= common_handled_fs;
            !access.is_empty()
        });
        self.rules_net_port.retain(|_, access| {
            *access &= common_handled_net;
            !access.is_empty()
        });

        // Second step: add the new rules from other, downgrade according to
        // common handled access rights, if they are not empty.
        for (path, access) in &other.rules_path_beneath {
            let downgraded_access = *access & common_handled_fs;
            if !downgraded_access.is_empty() {
                self.rules_path_beneath
                    .entry(path.clone())
                    .and_modify(|a| *a |= downgraded_access)
                    .or_insert(downgraded_access);
            }
        }
        for (port, access) in &other.rules_net_port {
            let downgraded_access = *access & common_handled_net;
            if !downgraded_access.is_empty() {
                self.rules_net_port
                    .entry(*port)
                    .and_modify(|a| *a |= downgraded_access)
                    .or_insert(downgraded_access);
            }
        }

        // Third step: merge variables.
        for (name, value) in other.variables.iter() {
            self.variables.extend(name.clone(), value.clone());
        }

        // Fourth step: downgrade the handled access rights.
        self.masks = common_masks;

        // Fifth step: downgrade the ABI version.
        self.abi = self.abi.min(other.abi);
    }

    pub fn parse_json<R>(reader: R) -> Result<Self, ParseJsonError>
    where
        R: std::io::Read,
    {
        let json = serde_json::from_reader::<_, NonEmptyStruct<JsonPolicy>>(reader)?;
        Ok(json.try_into()?)
    }

    #[cfg(feature = "toml")]
    pub fn parse_toml(data: &str) -> Result<Self, ParseTomlError> {
        // The TOML parser does not handle Read implementations,
        // see https://github.com/toml-rs/toml/issues/326
        let json: NonEmptyStruct<JsonPolicy> =
            toml::from_str::<NonEmptyStruct<TomlPolicy>>(data)?.convert();
        Ok(json.try_into()?)
    }

    /// Parse all policy files in a directory with the specified format.
    ///
    /// This method reads all files in the given directory that match the specified
    /// format's file extension and are regular files (not directories or hidden files
    /// starting with '.'). Each valid policy file is parsed and composed into
    /// a single policy using the [`compose`](Policy::compose) method.
    ///
    /// # Returns
    ///
    /// Returns a composed `Policy` from all valid policy files found in the
    /// directory, or ParseDirectoryError otherwise.
    pub fn parse_directory<T>(path: T, format: PolicyFormat) -> Result<Self, ParseDirectoryError>
    where
        T: AsRef<Path>,
    {
        let mut full_policy = None;
        let mut errors = BTreeMap::new();

        for entry in fs::read_dir(path)? {
            let path = entry?.path();
            if path.extension() != Some(format.extension().as_ref()) {
                continue;
            }

            if path
                .file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|name| name.starts_with('.'))
            {
                continue;
            }

            if !path.is_file() {
                continue;
            }

            match format {
                PolicyFormat::Json => match File::open(&path) {
                    Ok(file) => match Self::parse_json(file) {
                        Ok(policy) => full_policy.compose(&policy),
                        Err(e) => {
                            // Duplicated file names should be very rare when
                            // listing the content of a directory, and ignoring
                            // errors for now-removed files is OK.
                            errors.insert(path.clone(), e.into());
                        }
                    },
                    Err(e) => {
                        // Ignore race conditions when files are removed.
                        if e.kind() != std::io::ErrorKind::NotFound {
                            errors.insert(path.clone(), e.into());
                        }
                    }
                },
                #[cfg(feature = "toml")]
                PolicyFormat::Toml => match std::fs::read_to_string(&path) {
                    Ok(data) => match Self::parse_toml(data.as_str()) {
                        Ok(policy) => full_policy.compose(&policy),
                        Err(e) => {
                            errors.insert(path.clone(), e.into());
                        }
                    },
                    Err(e) => {
                        if e.kind() != std::io::ErrorKind::NotFound {
                            errors.insert(path.clone(), e.into());
                        }
                    }
                },
            }
        }

        if !errors.is_empty() {
            return Err(ParseDirectoryError::ParseFiles(errors));
        }
        full_policy.ok_or(ParseDirectoryError::NoPolicyFile)
    }

    pub fn resolve(self) -> Result<ResolvedPolicy, ResolveError> {
        self.try_into()
    }
}

#[test]
fn test_policy_empty() {
    let policy = Policy::empty(ABI::V6);
    assert_eq!(policy.abi, ABI::V6);
    assert_eq!(policy.masks, RulesetMasks::default());
}

pub trait OptionalPolicy {
    fn compose(&mut self, other: &Policy);
}

impl OptionalPolicy for Option<Policy> {
    fn compose(&mut self, other: &Policy) {
        match self {
            Some(policy) => policy.compose(other),
            None => *self = Some(other.clone()),
        }
    }
}

impl ResolvedPolicy {
    pub fn build_ruleset(&self) -> Result<(RulesetCreated, Vec<RuleError>), BuildRulesetError> {
        let mut ruleset = Ruleset::default();
        let ruleset_ref = &mut ruleset;
        if !self.handled_fs.is_empty() {
            ruleset_ref.handle_access(self.handled_fs)?;
        }
        if !self.handled_net.is_empty() {
            ruleset_ref.handle_access(self.handled_net)?;
        }
        if !self.scoped.is_empty() {
            ruleset_ref.scope(self.scoped)?;
        }
        let mut ruleset_created = ruleset.create()?;
        let ruleset_created_ref = &mut ruleset_created;
        let mut rule_errors = Vec::new();

        for (parent, allowed_access) in &self.rules_path_beneath {
            // TODO: Walk through all path and only open them once, including their
            // common parent directory to get a consistent hierarchy.
            let fd = match PathFd::new(parent) {
                Ok(fd) => fd,
                Err(e) => {
                    rule_errors.push(RuleError::PathFd(e));
                    continue;
                }
            };
            ruleset_created_ref.add_rule(PathBeneath::new(fd, *allowed_access))?;
        }

        for (port, allowed_access) in &self.rules_net_port {
            ruleset_created_ref.add_rule(
                // TODO: Check integer conversion in parse_json(), which would require changing the type of policy and specifying where the error is.
                NetPort::new((*port).try_into()?, *allowed_access),
            )?;
        }

        Ok((ruleset_created, rule_errors))
    }
}

impl TryFrom<Policy> for ResolvedPolicy {
    type Error = ResolveError;

    /// Resolve all (composed) variables but not local (synthetic) variables such as `abi.*`.
    fn try_from(policy: Policy) -> Result<Self, Self::Error> {
        let Policy {
            abi: _,
            variables,
            masks,
            rules_path_beneath: policy_rules_path_beneath,
            rules_net_port,
        } = policy;
        let RulesetMasks { fs, net, scope } = masks;
        let mut rules_path_beneath: BTreeMap<PathBuf, BitFlags<AccessFs>> = Default::default();
        for (path_beneath, access) in policy_rules_path_beneath {
            let set = variables.resolve(&path_beneath)?;
            for path in VecStringIterator::new(&set) {
                rules_path_beneath
                    .entry(PathBuf::from(path))
                    .and_modify(|a| *a |= access)
                    .or_insert(access);
            }
        }

        Ok(Self {
            handled_fs: fs,
            handled_net: net,
            scoped: scope,
            rules_path_beneath,
            rules_net_port,
        })
    }
}

#[cfg(test)]
mod tests_compose {
    use super::*;
    use landlock::{Access, ABI};

    #[test]
    fn test_empty_ruleset() {
        let mut c1 = Policy {
            masks: RulesetMasks {
                fs: AccessFs::Execute.into(),
                ..Default::default()
            },
            ..Policy::empty(ABI::V1)
        };
        let c2 = c1.clone();
        c1.compose(&c2);
        assert_eq!(c1, c2);
    }

    #[test]
    fn test_different_ruleset() {
        let mut c1 = Policy {
            masks: RulesetMasks {
                fs: AccessFs::Execute.into(),
                ..Default::default()
            },
            ..Policy::empty(ABI::V4)
        };
        let c2 = Policy {
            masks: RulesetMasks {
                net: AccessNet::BindTcp.into(),
                ..Default::default()
            },
            ..Policy::empty(ABI::V4)
        };
        let expect = Policy::empty(ABI::V4);
        c1.compose(&c2);
        assert_eq!(c1, expect);
    }

    #[test]
    fn test_compose_v1_v2_without_one_right() {
        let c1_access = AccessFs::from_all(ABI::V1);
        let mut c1 = Policy {
            masks: RulesetMasks {
                fs: c1_access,
                ..Default::default()
            },
            rules_path_beneath: [
                (TemplateString::from_text("/common"), c1_access),
                (TemplateString::from_text("/c1"), c1_access),
            ]
            .into(),
            ..Policy::empty(ABI::V1)
        };

        assert!(c1_access.contains(AccessFs::WriteFile));
        let c2_access = AccessFs::from_all(ABI::V2) & !AccessFs::WriteFile;
        let c2 = Policy {
            masks: RulesetMasks {
                fs: c2_access,
                ..Default::default()
            },
            rules_path_beneath: [
                (TemplateString::from_text("/common"), c2_access),
                (TemplateString::from_text("/c2"), c2_access),
            ]
            .into(),
            ..Policy::empty(ABI::V2)
        };

        c1.compose(&c2);
        assert_eq!(
            c1,
            Policy {
                masks: RulesetMasks {
                    fs: c1_access & c2_access,
                    ..Default::default()
                },
                rules_path_beneath: [
                    (TemplateString::from_text("/common"), c1_access & c2_access),
                    (TemplateString::from_text("/c1"), c1_access & c2_access),
                    (TemplateString::from_text("/c2"), c1_access & c2_access),
                ]
                .into(),
                ..Policy::empty(ABI::V1)
            }
        );
    }

    #[test]
    fn test_abi_minimum() {
        let c1 = Policy::empty(ABI::V1);
        let mut c1_mut = c1.clone();
        let mut c2_mut = Policy::empty(ABI::V2);

        c1_mut.compose(&c2_mut);
        assert_eq!(c1_mut.abi, ABI::V1);

        // Test commutativity
        c2_mut.compose(&c1);
        assert_eq!(c1_mut, c2_mut);
    }
}

# Landlock Policy

> **Work in progress:**  The policy specification is currently unstable.

See https://landlock.io

## Goal

The goal of Landlock Policy is to define a simple and flexible specification
for Landlock security policies, and to provide a reference implementation and
command-line tools that can parse both [JSON](https://json.org/) and
[TOML](https://toml.io) formats.  These formats are designed to be easy to
write, read, and parse, leveraging libraries available in a wide variety of
programming languages.

For instance, JSON can serve as an intermediate representation leveraged by
higher-level policy languages. In contrast, TOML is more user-friendly,
making it ideal for end users who need to document their policies and
minimize errors due to its less strict format.  Both formats translate to the
same semantics, ensuring that the security policies defined are consistent
regardless of the format used.

The associated library is designed to be embeddable in various programs,
facilitating sandboxing and providing well-defined security and compatibility
guarantees.

## Policy principles

### Policy composition and authority

A Landlock policy can be assembled by composing component compatibility policies
stored in separate files. Keeping these compatibility declarations separate
lets callers share and reuse them as policy snippets. It also lets ownership and
maintenance of a component's declarations be delegated to the party responsible
for that component, such as an application or library maintainer or a
distribution packager. Each policy describes the restrictions and resource
allowances under which its component is expected to work. Each owner is
responsible for maintaining and testing its component with the declarations in
that policy, and for retesting it after changing them.

For example, an application may depend on several libraries or plugins, each
delivered by a separate package and maintained by a different party. Each party
can own and maintain the compatibility policy for its component. A caller that
trusts all of these parties can compose their policies into one policy while
leaving each component owner responsible for its declarations.

Composing policies computes one policy intended to preserve the declared
compatibility requirements of every represented component. It does not combine
independent security requirements. Composition:

- uses the minimum effective policy ABI;
- intersects handled filesystem and network rights;
- intersects scoped rights;
- unions literal values declared for the same variable name; and
- unions path and port allowances, then limits them to the commonly handled
  rights.

Variable names share one composition-wide namespace. When multiple component
policies declare the same name, templates using that name expand over the union
of their literal values. Component owners must therefore coordinate shared names
or account for every resulting expansion in their compatibility tests.

This is intentionally compatibility-oriented. For ordinary access rights, the
composed policy only enforces a restriction if every selected policy declares
that its component tolerates that restriction. When every component handles a
right, the composed policy retains the resource allowances requested by all of
them.

A policy can therefore usually weaken the resulting confinement by excluding
handled rights or scopes, selecting a lower ABI, or requesting broad
allowances. The `refer` exclusion is exceptional: while another filesystem
right remains handled, it instead makes Landlock deny cross-directory
reparenting with `EXDEV`. Composition uses the minimum effective ABI, so one
lower-ABI component removes categories and rights added by later ABIs from the
composed masks. Parsing a future ABI on an older implementation likewise clamps
its masks to that implementation's recognized format ceiling. The caller must
trust every selected policy to state its component's compatibility requirements
accurately.
Composition provides confinement only to the extent implied by the selected
compatibility declarations. It is not a security boundary between mutually
distrusting policy authors. It cannot prove that a component was tested
correctly.

When restrictions come from independent security authorities and must not be
weakened by a component policy, apply separate Landlock ruleset layers instead
of composing the policies. Landlock makes denials from stacked layers
cumulative: for rights restricted by multiple layers, an operation must satisfy
every relevant layer, and an allowance in one layer cannot override another
layer's denial. For example, an application and its libraries may compose their
compatibility policies, while a service manager or system administrator applies
another layer containing mandatory site restrictions.

In short:

```text
policy composition          = preserve declared component compatibility by
                              enforcing only common handled restrictions and
                              retaining requested allowances for commonly
                              handled rights
stacked Landlock rulesets   = enforce every independent authority's restrictions
```

### JSON specification

The JSON format is used to define a Landlock security policy as specified by the
related [JSON schema](schema/landlock-policy.json). Schema validity checks the
structural contract but is not sufficient for parser acceptance. After ABI
clamping and group resolution, the parser rejects a policy whose filesystem,
network, and scope masks are all empty. The schema cannot express that aggregate
check. For an ABI already recognized by the parser, resolution uses that fixed
ABI. When a requested ABI is newer than the parser recognizes, however, a newer
library can raise the clamped format ceiling and change the resolved masks and
emptiness result. Validate deployable policies with the parser as well as the
schema.

As the Landlock kernel maintainers, we can guarantee that the specification and
the library will be kept in sync with kernel changes.

### Backward and forward compatibilities

Because the Linux kernel and user space might be updated independently according
to the their own upstream and downstream release cycles, a launcher (e.g.,
service managers, container runtimes) might be newer or older than the running
kernel.

In the case of an older kernel and a newer user space, an up-to-date Landlock
policy should remain as compatible as possible with older kernels. The default
behavior therefore follows a best-effort approach that protects users with the
supported functionality. See the [specification](schema/landlock-policy.json).

Every policy must declare a Landlock ABI version from 1 through 2^31 - 1, the
positive `i32` range. Declaring the ABI makes the policy's tested compatibility
contract explicit and keeps ABI-relative resolution stable within this format.
It does not preserve old-format semantics across a policy-format migration; see
[Policy format migration](#policy-format-migration). The ABI is not inferred
from the library version or the running kernel.

If an in-range requested ABI is newer than the policy format supports, the
parser uses the format's latest supported ABI to interpret the policy. This
implementation recognizes through ABI v7. ABI v7 adds restrict-self flags
outside the policy grammar, so its represented access-right and scope masks
remain unchanged from ABI v6. The resulting ruleset then follows rust-landlock's
compatibility handling for the running kernel, which may further reduce the
rights handled and enforced. This preserves the known subset of a future policy,
but it does not make unknown access names, properties, or rule types valid;
unknown syntax remains an error.

Parser-known access and scope names remain valid at every policy ABI. The ABI
defines the effective mask universe, so a known value outside that universe is
inert when excluded or allowed. Positive `abi.*` groups likewise resolve only
to rights supported by that ABI and may resolve to an empty set.

**TODO:**
In the case of an older user space and a newer kernel, it should be possible for
users to still leverage a subset of the newer kernel features.  This means that
the Landlock policy should be flexible enough to extend over the current
(soon old) specification.  Access rights are defined with meaningful keywords
(text), but to be able to protect users as much as possible, the policy format
should also handle numbers mapping to the kernel's UAPI bits. This should not
be seen as a replacement for the keyword representation of access rights, but as
a way to leverage some new features without being coupled too much with the
launcher's code.  The limit for supporting unknown features would be the
introduction of entirely new categories, such as new rule types or ruleset
properties. With the current fields, only unknown access rights would be
supported. However, if raw access rights are used, the library will not be able
to provide the same level of compatibility guarantees.  See
https://github.com/opencontainers/runtime-spec/pull/1241#pullrequestreview-2595870681

### Concise policies

The policy format should ease conciseness (e.g., by handling arrays of paths).

The policy format should handle groups of access rights per [Landlock ABI
version](https://landlock.io/rust-landlock/landlock/enum.ABI.html).

### Secure defaults

Most policies should declare their tested ABI, add narrow path or port
allowances, and omit `ruleset` entirely. The parser starts filesystem and
network handling, and process scoping, with every right supported by the
effective policy ABI. A policy containing only an ABI is therefore valid and
selects these complete masks without adding resource allowances.

The optional inverse fields are advanced compatibility controls, not ordinary
permissions:

- `unhandledAccessFs` (`unhandled_access_fs` in TOML) removes rights from the
  Landlock `handled_access_fs` mask;
- `unhandledAccessNet` (`unhandled_access_net`) removes rights from
  `handled_access_net`;
- `unscoped` removes rights from `scoped`.

Omitting a field, setting an optional JSON property to `null`, or using an empty
array removes nothing. Omission is the canonical, shortest, and strongest
representation. Removing a right or scope usually stops this Landlock layer
from restricting it globally. The `refer` right is exceptional: leaving it
unhandled while another filesystem right is handled makes Landlock deny
cross-directory reparenting with `EXDEV`. No exclusion overrides restrictions
from another Landlock layer or security mechanism.

Repeated ruleset entries are source fragments: their exclusions are unioned
before resolving one UAPI mask, not installed as independent Landlock layers.
Path and port rules remain positive allowances and never add rights back to
handled masks. Because inverse arrays reduce handled or scoped rights, use them
only for tested compatibility requirements.

A directly parsed policy whose final three masks are empty is rejected.
Composition remains infallible and intersects concrete masks, so it may produce
an empty policy; building that composition then fails because there is no
handled access. Independent security authorities should instead install
separate stacked Landlock layers.

### Compatibility exclusions (advanced)

First try a targeted path or port allowance when an application needs access.
Use an inverse field only when complete handling remains incompatible and the
policy owner has reviewed the resulting global loss of enforcement. For
example, this exceptional policy handles every ABI 5 right except device-control
operations while granting read/write access below `/tmp`:

```json
{
  "abi": 5,
  "ruleset": [{
    "unhandledAccessFs": ["ioctl_dev"]
  }],
  "pathBeneath": [{
    "allowedAccess": ["abi.read_write"],
    "parent": ["/tmp"]
  }]
}
```

```toml
abi = 5

[[ruleset]]
unhandled_access_fs = ["ioctl_dev"]

[[path_beneath]]
allowed_access = ["abi.read_write"]
parent = ["/tmp"]
```

A concrete exclusion is fixed to that known right. An `abi.*` group is an
ABI-relative, future-expanding contract. Inverse values use ordinary set union:
duplicates and `abi.all` beside other known items are valid and idempotent.
Omission, JSON null, and an empty array all mean no exclusions, which lets
scripts and serializers emit computed optional sets without deleting empty
properties.

Rules are reconciled after exclusions by intersecting every concrete or group
allowance with the final handled mask. A fully masked rule is skipped. This does
not grant an unhandled operation: this Landlock layer already does not restrict
that operation, and other Landlock layers or security mechanisms may still deny
it.

Excluding `refer` is an exact handled-mask operation, not permission to reparent
files. Landlock implicitly denies cross-directory reparenting when another
filesystem right is handled unless a matching `refer` rule permits it. To avoid
`EXDEV`, prefer targeted `refer` allowances; where that is unsuitable, use the
application's documented copy/write/remove fallback.

If an exclusion is necessary, prefer one concrete right over a semantic group.
A group is a future-expanding compatibility contract, and `abi.all` should be a
last resort used only to permanently disable a category. Because process scopes
have no path or port allowance rules, every `unscoped` item is likewise a global
compatibility decision. Changing a policy ABI, exclusion, variable, or allowance
changes its compatibility contract and requires retesting by the component
owner.

## Reference implementation

### Shared Library

This repository enables developers to build an ELF shared object library, which
can then be used by any program and most programming languages via a foreign
function interface (FFI) and a [C API](c/landlock-policy.h).

To install this library, first install
[cargo-c](https://github.com/lu-zero/cargo-c) using your package manager or with
`cargo install cargo-c`, and then run these commands:

```sh
cargo cinstall --package=landlock-policy-ffi --release --prefix=/usr/local --destdir=out
sudo cp -dr out/usr/local/* /usr/local/
```

The library is then usable via `pkg-config` as `landlock-policy`. See the [C
example](c/examples/sandboxer.c) and its [Makefile](c/examples/Makefile).

### Resilient

The parser should be resilient against any input.

### Native Rust interface

Rust is used as the referenced implementation, which help build and maintain a
robust library while still being able to convert it to a shared object. This
Rust crate can be used as a standalone library.

## Testing

This repository contains the policy specification and a test suite that
can be used to test the library implementation against a set of valid and
invalid samples. This could also be used to test Landlock libraries to make sure
the execution traces are similar.

The test suite uses an in-process JSON schema validator by default.  To also
validate every inline JSON snippet with `check-jsonschema`, install it and run:

```sh
LANDLOCK_POLICY_TEST_JSON_SCHEMA=1 cargo test --locked --all
```

When set, `LANDLOCK_POLICY_TEST_JSON_SCHEMA` accepts `0` or `1`.  Enabling it
requires the `check-jsonschema` executable to be available in `PATH`.

## Command-line tools

### landlock-policy

`landlock-policy` is the policy development, inspection, and transformation
tool. It currently prints the canonical JSON schema and is intended to grow
operations for debugging, linting, formatting, updating, merging, and
translating policy inputs:

```sh
git clone https://github.com/landlock-lsm/landlock-policy
cd landlock-policy
cargo install --path landlock-policy-cli
landlock-policy schema
```

### landlock-exec

`landlock-exec` is the policy enforcement and execution wrapper. It applies
one effective policy composed from JSON or TOML policy inputs and replaces
itself with the confined command. It is an intentionally minimal reference
wrapper; end users looking for a full-featured sandboxing tool should use
[Island](https://github.com/landlock-lsm/island) instead.

```sh
git clone https://github.com/landlock-lsm/landlock-policy
cd landlock-policy
cargo install --path landlock-exec
landlock-exec --json examples/mini-write-tmp.json sh
```

Component compatibility policies can be composed by specifying `--json` or
`--toml` (and related file or directory paths) several times. See
[Policy composition and authority](#policy-composition-and-authority)
before combining policies from different maintainers.

## TOML policy example

Here is an abridged [TOML policy](examples/micro-var.toml) that uses variables,
access right groups, and a list of directory hierarchies for conciseness.

```toml
abi = 5

# The omitted ruleset defaults to all rights supported by ABI 5.
[[variable]]
name = "tmp"
literal = ["/tmp", "/var/tmp"]

[[variable]]
name = "home"
literal = ["/root", "/home"]

[[variable]]
name = "config"
literal = ["/etc"]

# Main system file hierarchies can be read and executed.
[[path_beneath]]
allowed_access = ["abi.read_execute"]
parent = ["/bin", "/lib", "/usr", "/dev", "/proc", "${config}"]

# Only allow writing to temporary and home directories.
[[path_beneath]]
allowed_access = ["abi.read_write"]
parent = ["${tmp}", "${home}"]
```

We can get a view of the created Landlock rules:
```sh
landlock-exec --toml examples/micro-var.toml --debug date
```

## Migration from landlockconfig

`landlockconfig` was the previous name of this project and its public
interfaces. Because these interfaces have not been released from this
repository, they are replaced without compatibility aliases:

- The repository and Rust crate move from `landlockconfig` to
  `landlock-policy`; the FFI crate moves from `landlockconfig_ffi` to
  `landlock-policy-ffi`.
- The schema moves from `schema/landlockconfig.json` to
  `schema/landlock-policy.json`.
- The C library, pkg-config module, header, object type, and function prefix
  move from `liblandlockconfig`, `landlockconfig`, `landlockconfig.h`,
  `struct landlockconfig`, and `landlockconfig_*` to `liblandlock-policy`,
  `landlock-policy`, `landlock-policy.h`, `struct landlock_policy`, and
  `landlock_policy_*`.
- The former `llconfig schema` command is now `landlock-policy schema`;
  `llconfig run` is now `landlock-exec` with the same options and command
  arguments, but without the `run` subcommand.
- The Debian `liblandlockconfig0`, `liblandlockconfig-dev`, and `llconfig`
  packages are replaced by `liblandlock-policy0`, `liblandlock-policy-dev`,
  `landlock-policy`, and `landlock-exec`.

## Policy format migration

> **Security migration warning:** Successful parsing does not show that an old
> policy retained its meaning. An old policy can already declare an ABI, contain
> none of the removed positive handled or scoped fields, and still become much
> stricter. Previously, a narrow path or port rule implicitly handled only its
> listed rights; this format derives complete ABI masks, so the same source can
> deny all other filesystem, network, and scoped operations that lack an
> allowance. Semantically convert and retest every old policy rather than
> treating parser acceptance as migration evidence.

Policies accepted by earlier versions may require these updates:

- Every policy must declare the Landlock ABI against which it was tested.
  Choose the tested compatibility contract rather than blindly selecting the
  newest ABI.
- The positive `handled_access_fs`, `handled_access_net`, and `scoped` fields
  are replaced by inverse `unhandled_access_fs`, `unhandled_access_net`, and
  `unscoped` fields. Omission, JSON null, or an empty array selects the complete
  effective-ABI mask.

To migrate, first resolve the old policy at a selected, tested ABI. Its old
filesystem and network masks include access named by path and port rules:

```text
old_base_fs = union(old handled_access_fs arrays), if present; empty otherwise
old_base_net = union(old handled_access_net arrays), if present; empty otherwise
old_base_scope = union(old scoped arrays), if present; empty otherwise
old_final_fs = old_base_fs | old_path_rule_access
old_final_net = old_base_net | old_port_rule_access
old_final_scope = old_base_scope
unhandled_access_fs = fs_from_all(selected_abi) - old_final_fs
unhandled_access_net = net_from_all(selected_abi) - old_final_net
unscoped = scope_from_all(selected_abi) - old_final_scope
```

Serialize that complement, not the old positive array. Migration cannot infer
whether later rights should be excluded as fixed concrete names, through a
future-expanding semantic group, or permanently with `abi.all`; the policy
owner must choose and test that future contract.

For example, an old policy that handled only filesystem execution resolves at
ABI 6 to an execution-only filesystem mask and empty network and scope masks.
Its direct concrete complement is verbose; if the owner's durable intent is to
permanently disable network and scoping, it may begin as:

```toml
abi = 6

[[ruleset]]
unhandled_access_fs = [
  "write_file", "read_file", "read_dir", "remove_dir", "remove_file",
  "make_char", "make_dir", "make_reg", "make_sock", "make_fifo",
  "make_block", "make_sym", "refer", "truncate", "ioctl_dev",
]
unhandled_access_net = ["abi.all"]
unscoped = ["abi.all"]
```

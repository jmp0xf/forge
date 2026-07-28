//! Cheap architecture guards for stable, mechanically checkable invariants.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

fn repository_root() -> Result<PathBuf, Box<dyn std::error::Error>> {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .map(Path::to_path_buf)
        .ok_or_else(|| "xtask manifest directory has no parent".into())
}

#[test]
fn only_the_runtime_process_module_constructs_product_subprocesses()
-> Result<(), Box<dyn std::error::Error>> {
    let root = repository_root()?;
    let source_root = root.join("crates");
    let mut violations = Vec::new();
    for path in rust_source_files(&source_root)? {
        if path.ends_with("forge-runtime/src/process.rs")
            || path
                .components()
                .any(|component| component.as_os_str() == "tests")
        {
            continue;
        }
        let source = fs::read_to_string(&path)?;
        if constructs_product_subprocess(&source) {
            violations.push(path);
        }
    }
    assert!(
        violations.is_empty(),
        "external commands bypass forge-runtime::process: {violations:?}"
    );
    Ok(())
}

fn constructs_product_subprocess(source: &str) -> bool {
    let product_source = source_without_test_items(source);
    product_source.contains("std::process::Command")
        || product_source.contains("use std::process::Command")
        || product_source.contains("Command::new(")
}

fn source_without_test_items(source: &str) -> String {
    const TEST_ITEM_ATTRIBUTE: &str = "#[cfg(test)]";

    let mut product = String::with_capacity(source.len());
    let mut remaining = source;
    while let Some(start) = remaining.find(TEST_ITEM_ATTRIBUTE) {
        product.push_str(&remaining[..start]);
        let item_start = start + TEST_ITEM_ATTRIBUTE.len();
        let Some(end) = rust_test_item_end(remaining, item_start) else {
            // An unfamiliar or malformed layout is scanned conservatively instead of creating a
            // product-code blind spot.
            product.push_str(&remaining[start..]);
            return product;
        };
        product.extend(
            remaining[start..end]
                .bytes()
                .filter(|byte| *byte == b'\n')
                .map(|_| '\n'),
        );
        remaining = &remaining[end..];
    }
    product.push_str(remaining);
    product
}

fn rust_test_item_end(source: &str, start: usize) -> Option<usize> {
    let bytes = source.as_bytes();
    let mut index = start;
    while index < bytes.len() {
        if bytes[index..].starts_with(b"//") {
            index = bytes[index..]
                .iter()
                .position(|byte| *byte == b'\n')
                .map_or(bytes.len(), |offset| index + offset + 1);
            continue;
        }
        if bytes[index..].starts_with(b"/*") {
            index = rust_block_comment_end(bytes, index)?;
            continue;
        }
        if bytes[index] == b'"' {
            index = quoted_rust_literal_end(bytes, index, b'"')?;
            continue;
        }
        if bytes[index] == b'\'' {
            if let Some(end) = rust_character_literal_end(bytes, index) {
                index = end;
                continue;
            }
        }
        if bytes[index] == b'r' {
            if let Some(end) = raw_rust_string_end(bytes, index) {
                index = end;
                continue;
            }
        }
        match bytes[index] {
            b'{' => return matching_rust_block_end(source, index),
            b';' => return Some(index + 1),
            _ => index += 1,
        }
    }
    None
}

fn matching_rust_block_end(source: &str, opening_brace: usize) -> Option<usize> {
    let bytes = source.as_bytes();
    if bytes.get(opening_brace) != Some(&b'{') {
        return None;
    }
    let mut index = opening_brace;
    let mut depth = 0_usize;
    while index < bytes.len() {
        if bytes[index..].starts_with(b"//") {
            index = bytes[index..]
                .iter()
                .position(|byte| *byte == b'\n')
                .map_or(bytes.len(), |offset| index + offset + 1);
            continue;
        }
        if bytes[index..].starts_with(b"/*") {
            index = rust_block_comment_end(bytes, index)?;
            continue;
        }
        if bytes[index] == b'"' {
            index = quoted_rust_literal_end(bytes, index, b'"')?;
            continue;
        }
        if bytes[index] == b'\'' {
            if let Some(end) = rust_character_literal_end(bytes, index) {
                index = end;
                continue;
            }
        }
        if bytes[index] == b'r' {
            if let Some(end) = raw_rust_string_end(bytes, index) {
                index = end;
                continue;
            }
        }
        match bytes[index] {
            b'{' => depth = depth.checked_add(1)?,
            b'}' => {
                depth = depth.checked_sub(1)?;
                if depth == 0 {
                    return Some(index + 1);
                }
            }
            _ => {}
        }
        index += 1;
    }
    None
}

fn rust_block_comment_end(bytes: &[u8], start: usize) -> Option<usize> {
    let mut index = start + 2;
    let mut depth = 1_usize;
    while index < bytes.len() {
        if bytes[index..].starts_with(b"/*") {
            depth = depth.checked_add(1)?;
            index += 2;
        } else if bytes[index..].starts_with(b"*/") {
            depth = depth.checked_sub(1)?;
            index += 2;
            if depth == 0 {
                return Some(index);
            }
        } else {
            index += 1;
        }
    }
    None
}

fn quoted_rust_literal_end(bytes: &[u8], start: usize, quote: u8) -> Option<usize> {
    let mut index = start + 1;
    while index < bytes.len() {
        match bytes[index] {
            b'\\' => index = index.checked_add(2)?,
            byte if byte == quote => return Some(index + 1),
            _ => index += 1,
        }
    }
    None
}

fn rust_character_literal_end(bytes: &[u8], start: usize) -> Option<usize> {
    let next = *bytes.get(start + 1)?;
    if next == b'\\' {
        return quoted_rust_literal_end(bytes, start, b'\'');
    }
    let character_width = std::str::from_utf8(&bytes[start + 1..])
        .ok()?
        .chars()
        .next()?
        .len_utf8();
    (bytes.get(start + 1 + character_width) == Some(&b'\'')).then_some(start + 2 + character_width)
}

fn raw_rust_string_end(bytes: &[u8], start: usize) -> Option<usize> {
    let mut quote = start + 1;
    while bytes.get(quote) == Some(&b'#') {
        quote += 1;
    }
    if bytes.get(quote) != Some(&b'"') {
        return None;
    }
    let hashes = quote - start - 1;
    let mut index = quote + 1;
    while index < bytes.len() {
        if bytes[index] == b'"'
            && bytes.get(index + 1..index + 1 + hashes) == Some(&bytes[start + 1..quote])
        {
            return Some(index + 1 + hashes);
        }
        index += 1;
    }
    None
}

#[test]
fn process_guard_excludes_unit_test_module_without_hiding_product_code() {
    let tests_only = "fn product() {}\n#[cfg(test)]\nmod tests {\n    fn fixture() { Command::new(\"chmod\"); }\n}\n";
    let product_before = "fn product() { Command::new(\"tool\"); }\n#[cfg(test)]\nmod tests {\n}\n";
    let product_after = "#[cfg(test)]\nmod tests {\n    fn fixture() { Command::new(\"chmod\"); }\n}\nfn product() { Command::new(\"tool\"); }\n";
    let misleading_test_data = "fn product() {}\n#[cfg(test)]\nmod tests {\n    const JSON: &str = \"{\\n}\\n\";\n    const RAW: &str = r#\"} // not syntax\"#;\n    /* nested { comment } */\n    fn fixture() { Command::new(\"chmod\"); }\n}\n";
    let test_only_impl = "fn product() {}\n#[cfg(test)]\nimpl Fixture {\n    fn create() { Command::new(\"chmod\"); }\n}\n";
    let test_only_function =
        "fn product() {}\n#[cfg(test)]\nfn fixture() { Command::new(\"chmod\"); }\n";

    assert!(!constructs_product_subprocess(tests_only));
    assert!(!constructs_product_subprocess(misleading_test_data));
    assert!(!constructs_product_subprocess(test_only_impl));
    assert!(!constructs_product_subprocess(test_only_function));
    assert!(constructs_product_subprocess(product_before));
    assert!(constructs_product_subprocess(product_after));
}

#[test]
fn production_crate_sources_do_not_use_unchecked_panic_shortcuts()
-> Result<(), Box<dyn std::error::Error>> {
    let root = repository_root()?;
    let mut violations = Vec::new();
    for entry in fs::read_dir(root.join("crates"))? {
        let entry = entry?;
        let source_root = entry.path().join("src");
        if !source_root.is_dir() {
            continue;
        }
        for path in rust_source_files(&source_root)? {
            let source = fs::read_to_string(&path)?;
            let product_source = source_without_test_items(&source);
            for (line_index, line) in product_source.lines().enumerate() {
                if unchecked_panic_token(line).is_some() {
                    violations.push(format!("{}:{}", path.display(), line_index + 1));
                }
            }
        }
    }
    assert!(
        violations.is_empty(),
        "crate source contains unchecked panic shortcuts: {violations:?}"
    );
    Ok(())
}

fn unchecked_panic_token(line: &str) -> Option<&'static str> {
    [
        ".unwrap(",
        ".expect(",
        "panic!(",
        "unreachable!(",
        "todo!(",
        "unimplemented!(",
    ]
    .into_iter()
    .find(|token| line.contains(token))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum ProductIdentityKind {
    DisplayName,
    CliReference,
    ConfigFile,
    MachineNamespace,
    ManagedMarker,
    ProductNamespace,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct AuthorizedProductIdentityUse {
    path: &'static str,
    kind: ProductIdentityKind,
    expected_literals: usize,
    reason: &'static str,
}

// `forge-core::branding` and `forge-schema` are the identity definition points authorized by
// ADR-0001. ADR-0006 makes managed markers a published interface, so their syntax has a stricter
// single definition point where parser and renderer evolve together; unlike ordinary identity
// uses, marker literals cannot be authorized in the consumer ledger.
const PRODUCT_IDENTITY_DEFINITION_PATHS: &[&str] = &[
    "crates/forge-core/src/branding.rs",
    "crates/forge-schema/src/contracts.rs",
    "crates/forge-schema/src/lib.rs",
];
const MANAGED_MARKER_DEFINITION_PATH: &str = "crates/forge-render/src/managed_block.rs";

const USER_FACING_IDENTITY: &str =
    "user-facing CLI output or diagnostics must name the product or an executable command";
const CONFIG_COMPATIBILITY: &str = "configuration discovery, diagnostics, or compatibility logic must recognize the stable file name";
const MACHINE_PROTOCOL: &str = "versioned protocol, schema compatibility, or hash-domain separation requires the stable namespace";
const OS_RESOURCE_NAME: &str =
    "private paths, thread names, and internal resource labels retain a diagnosable product prefix";

macro_rules! authorize_identity {
    ($path:literal, $kind:ident, $count:literal, $reason:ident) => {
        AuthorizedProductIdentityUse {
            path: $path,
            kind: ProductIdentityKind::$kind,
            expected_literals: $count,
            reason: $reason,
        }
    };
}

#[rustfmt::skip]
const AUTHORIZED_PRODUCT_IDENTITY_USES: &[AuthorizedProductIdentityUse] = &[
    authorize_identity!("crates/forge-cli/src/adapter_manifest.rs", DisplayName, 1, USER_FACING_IDENTITY),
    authorize_identity!("crates/forge-cli/src/adapters.rs", DisplayName, 9, USER_FACING_IDENTITY),
    authorize_identity!("crates/forge-cli/src/adapters.rs", CliReference, 3, USER_FACING_IDENTITY),
    authorize_identity!("crates/forge-cli/src/args.rs", CliReference, 1, USER_FACING_IDENTITY),
    authorize_identity!("crates/forge-cli/src/doctor.rs", DisplayName, 14, USER_FACING_IDENTITY),
    authorize_identity!("crates/forge-cli/src/doctor.rs", CliReference, 20, USER_FACING_IDENTITY),
    authorize_identity!("crates/forge-cli/src/doctor.rs", ConfigFile, 1, CONFIG_COMPATIBILITY),
    authorize_identity!("crates/forge-cli/src/evidence.rs", DisplayName, 4, USER_FACING_IDENTITY),
    authorize_identity!("crates/forge-cli/src/evidence.rs", CliReference, 6, USER_FACING_IDENTITY),
    authorize_identity!("crates/forge-cli/src/evidence_state.rs", MachineNamespace, 10, MACHINE_PROTOCOL),
    authorize_identity!("crates/forge-cli/src/evidence_view.rs", DisplayName, 6, USER_FACING_IDENTITY),
    authorize_identity!("crates/forge-cli/src/evidence_view.rs", CliReference, 1, USER_FACING_IDENTITY),
    authorize_identity!("crates/forge-cli/src/explain.rs", DisplayName, 3, USER_FACING_IDENTITY),
    authorize_identity!("crates/forge-cli/src/init.rs", DisplayName, 9, USER_FACING_IDENTITY),
    authorize_identity!("crates/forge-cli/src/init.rs", CliReference, 3, USER_FACING_IDENTITY),
    authorize_identity!("crates/forge-cli/src/init.rs", ConfigFile, 4, CONFIG_COMPATIBILITY),
    authorize_identity!("crates/forge-cli/src/init.rs", MachineNamespace, 1, MACHINE_PROTOCOL),
    authorize_identity!("crates/forge-cli/src/main.rs", DisplayName, 7, USER_FACING_IDENTITY),
    authorize_identity!("crates/forge-cli/src/main.rs", CliReference, 3, USER_FACING_IDENTITY),
    authorize_identity!("crates/forge-cli/src/next.rs", DisplayName, 2, USER_FACING_IDENTITY),
    authorize_identity!("crates/forge-cli/src/next.rs", CliReference, 2, USER_FACING_IDENTITY),
    authorize_identity!("crates/forge-core/src/control.rs", MachineNamespace, 1, MACHINE_PROTOCOL),
    authorize_identity!("crates/forge-core/src/evidence.rs", MachineNamespace, 2, MACHINE_PROTOCOL),
    authorize_identity!("crates/forge-core/src/evidence.rs", ProductNamespace, 1, MACHINE_PROTOCOL),
    authorize_identity!("crates/forge-core/src/fingerprint.rs", MachineNamespace, 25, MACHINE_PROTOCOL),
    authorize_identity!("crates/forge-core/src/policy.rs", MachineNamespace, 2, MACHINE_PROTOCOL),
    authorize_identity!("crates/forge-core/src/risk.rs", ConfigFile, 1, CONFIG_COMPATIBILITY),
    authorize_identity!("crates/forge-core/src/scope.rs", MachineNamespace, 2, MACHINE_PROTOCOL),
    authorize_identity!("crates/forge-core/src/wire.rs", MachineNamespace, 4, MACHINE_PROTOCOL),
    authorize_identity!("crates/forge-detect/src/assets.rs", ConfigFile, 2, CONFIG_COMPATIBILITY),
    authorize_identity!("crates/forge-detect/src/assets.rs", ProductNamespace, 1, MACHINE_PROTOCOL),
    authorize_identity!("crates/forge-detect/src/config.rs", DisplayName, 1, USER_FACING_IDENTITY),
    authorize_identity!("crates/forge-detect/src/config.rs", ConfigFile, 4, CONFIG_COMPATIBILITY),
    authorize_identity!("crates/forge-detect/src/go.rs", DisplayName, 1, USER_FACING_IDENTITY),
    authorize_identity!("crates/forge-detect/src/go.rs", MachineNamespace, 1, MACHINE_PROTOCOL),
    authorize_identity!("crates/forge-detect/src/inventory_cache.rs", MachineNamespace, 6, MACHINE_PROTOCOL),
    authorize_identity!("crates/forge-detect/src/model.rs", DisplayName, 6, USER_FACING_IDENTITY),
    authorize_identity!("crates/forge-detect/src/repository.rs", DisplayName, 2, USER_FACING_IDENTITY),
    authorize_identity!("crates/forge-detect/src/repository.rs", CliReference, 1, USER_FACING_IDENTITY),
    authorize_identity!("crates/forge-detect/src/repository.rs", MachineNamespace, 2, MACHINE_PROTOCOL),
    authorize_identity!("crates/forge-detect/src/rust.rs", MachineNamespace, 1, MACHINE_PROTOCOL),
    authorize_identity!("crates/forge-render/src/adapters.rs", CliReference, 1, USER_FACING_IDENTITY),
    authorize_identity!("crates/forge-render/src/digest.rs", MachineNamespace, 1, MACHINE_PROTOCOL),
    authorize_identity!("crates/forge-render/src/managed_block.rs", MachineNamespace, 1, MACHINE_PROTOCOL),
    authorize_identity!("crates/forge-render/src/plan.rs", DisplayName, 3, USER_FACING_IDENTITY),
    authorize_identity!("crates/forge-render/src/plan.rs", MachineNamespace, 1, MACHINE_PROTOCOL),
    authorize_identity!("crates/forge-runtime/src/fs.rs", ProductNamespace, 1, OS_RESOURCE_NAME),
    authorize_identity!("crates/forge-runtime/src/git.rs", DisplayName, 1, USER_FACING_IDENTITY),
    authorize_identity!("crates/forge-runtime/src/git.rs", CliReference, 1, USER_FACING_IDENTITY),
    authorize_identity!("crates/forge-runtime/src/git.rs", ProductNamespace, 1, OS_RESOURCE_NAME),
    authorize_identity!("crates/forge-runtime/src/hash.rs", MachineNamespace, 1, MACHINE_PROTOCOL),
    authorize_identity!("crates/forge-runtime/src/process.rs", MachineNamespace, 1, MACHINE_PROTOCOL),
    authorize_identity!("crates/forge-runtime/src/process.rs", ProductNamespace, 2, OS_RESOURCE_NAME),
    authorize_identity!("crates/forge-runtime/src/scope.rs", DisplayName, 2, USER_FACING_IDENTITY),
    authorize_identity!("crates/forge-runtime/src/scope.rs", MachineNamespace, 1, MACHINE_PROTOCOL),
    authorize_identity!("crates/forge-runtime/src/state.rs", CliReference, 2, OS_RESOURCE_NAME),
    authorize_identity!("crates/forge-runtime/src/state/evidence.rs", MachineNamespace, 2, MACHINE_PROTOCOL),
    authorize_identity!("crates/forge-runtime/src/state/evidence.rs", ProductNamespace, 2, OS_RESOURCE_NAME),
    authorize_identity!("crates/forge-runtime/src/toolchain.rs", MachineNamespace, 1, MACHINE_PROTOCOL),
];

#[derive(Debug, Clone, PartialEq, Eq)]
struct RustStringLiteral {
    line: usize,
    text: String,
}

#[test]
fn product_identity_literals_are_centralized_or_explicitly_authorized()
-> Result<(), Box<dyn std::error::Error>> {
    let root = repository_root()?;
    let mut observed = BTreeMap::<(String, ProductIdentityKind), Vec<RustStringLiteral>>::new();
    for crate_entry in fs::read_dir(root.join("crates"))? {
        let source_root = crate_entry?.path().join("src");
        if !source_root.is_dir() {
            continue;
        }
        for path in rust_source_files(&source_root)? {
            let relative = slash_path(path.strip_prefix(&root)?);
            let source = fs::read_to_string(&path)?;
            let product_source = source_without_test_items(&source);
            for literal in rust_string_literals(&product_source) {
                for kind in product_identity_kinds(&literal.text) {
                    if is_product_identity_definition(&relative, kind) {
                        continue;
                    }
                    observed
                        .entry((relative.clone(), kind))
                        .or_default()
                        .push(literal.clone());
                }
            }
        }
    }

    let authorized = AUTHORIZED_PRODUCT_IDENTITY_USES
        .iter()
        .map(|entry| ((entry.path, entry.kind), entry))
        .collect::<BTreeMap<_, _>>();
    assert_eq!(
        authorized.len(),
        AUTHORIZED_PRODUCT_IDENTITY_USES.len(),
        "product identity authorization ledger contains duplicate path/kind entries"
    );
    assert!(
        AUTHORIZED_PRODUCT_IDENTITY_USES
            .iter()
            .all(|entry| { entry.expected_literals > 0 && !entry.reason.trim().is_empty() })
    );
    assert!(
        AUTHORIZED_PRODUCT_IDENTITY_USES
            .iter()
            .all(|entry| entry.kind != ProductIdentityKind::ManagedMarker),
        "managed-marker literals must use the centralized parser and renderer, not ledger authorization"
    );
    let mut violations = Vec::new();
    for ((path, kind), literals) in &observed {
        match authorized.get(&(path.as_str(), *kind)) {
            Some(entry) if entry.expected_literals == literals.len() => {}
            Some(entry) => violations.push(format!(
                "{path} {kind:?}: observed {} literals, expected {} ({})",
                literals.len(),
                entry.expected_literals,
                entry.reason
            )),
            None => violations.push(format!(
                "{path} {kind:?}: unauthorized literals {}",
                format_identity_literals(literals)
            )),
        }
    }
    for entry in AUTHORIZED_PRODUCT_IDENTITY_USES {
        let observed_count = observed
            .get(&(entry.path.to_owned(), entry.kind))
            .map_or(0, Vec::len);
        if observed_count == 0 && entry.expected_literals != 0 {
            violations.push(format!(
                "{} {:?}: stale authorization expected {} literals ({})",
                entry.path, entry.kind, entry.expected_literals, entry.reason
            ));
        }
    }

    assert!(
        violations.is_empty(),
        "ADR-0001 product identity literals must be centralized or explicitly authorized:\n{}",
        violations.join("\n")
    );
    Ok(())
}

fn is_product_identity_definition(path: &str, kind: ProductIdentityKind) -> bool {
    if kind == ProductIdentityKind::ManagedMarker {
        path == MANAGED_MARKER_DEFINITION_PATH
    } else {
        PRODUCT_IDENTITY_DEFINITION_PATHS.contains(&path)
    }
}

fn slash_path(path: &Path) -> String {
    path.components()
        .map(|component| component.as_os_str().to_string_lossy())
        .collect::<Vec<_>>()
        .join("/")
}

fn format_identity_literals(literals: &[RustStringLiteral]) -> String {
    literals
        .iter()
        .map(|literal| format!("line {} {:?}", literal.line, literal.text))
        .collect::<Vec<_>>()
        .join(", ")
}

fn product_identity_kinds(literal: &str) -> BTreeSet<ProductIdentityKind> {
    let mut kinds = BTreeSet::new();
    if contains_ascii_word(literal, "Forge") {
        kinds.insert(ProductIdentityKind::DisplayName);
    }
    if literal.contains("forge.toml") {
        kinds.insert(ProductIdentityKind::ConfigFile);
    }
    if contains_machine_namespace(literal) {
        kinds.insert(ProductIdentityKind::MachineNamespace);
    }
    if literal.contains("forge:begin") || literal.contains("forge:end") {
        kinds.insert(ProductIdentityKind::ManagedMarker);
    }
    if literal.contains(".forge") || literal.contains("forge/") || literal.contains("forge-") {
        kinds.insert(ProductIdentityKind::ProductNamespace);
    }
    if contains_cli_reference(literal) {
        kinds.insert(ProductIdentityKind::CliReference);
    }
    kinds
}

fn contains_ascii_word(value: &str, word: &str) -> bool {
    value.match_indices(word).any(|(start, _)| {
        let before = value[..start].bytes().next_back();
        let after = value[start + word.len()..].bytes().next();
        before.is_none_or(|byte| !is_word_byte(byte))
            && after.is_none_or(|byte| !is_word_byte(byte))
    })
}

const fn is_word_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_'
}

fn contains_machine_namespace(value: &str) -> bool {
    value.match_indices("forge.").any(|(start, _)| {
        let before = value[..start].bytes().next_back();
        before.is_none_or(|byte| !is_word_byte(byte)) && !value[start..].starts_with("forge.toml")
    })
}

fn contains_cli_reference(value: &str) -> bool {
    const COMMANDS: &[&str] = &[
        "--help",
        "-C",
        "adapters",
        "completions",
        "doctor",
        "evidence",
        "explain",
        "init",
        "next",
        "schema",
        "version",
    ];
    value.match_indices("forge").any(|(start, _)| {
        let before = value[..start].bytes().next_back();
        if before.is_some_and(is_word_byte) {
            return false;
        }
        let rest = &value[start + "forge".len()..];
        if rest.is_empty() {
            return start == 0 || before == Some(b'`');
        }
        let Some(rest) = rest.strip_prefix(char::is_whitespace) else {
            return false;
        };
        let rest = rest.trim_start();
        COMMANDS.iter().any(|command| {
            rest.strip_prefix(command)
                .is_some_and(|suffix| suffix.bytes().next().is_none_or(|byte| !is_word_byte(byte)))
        })
    })
}

fn rust_string_literals(source: &str) -> Vec<RustStringLiteral> {
    let bytes = source.as_bytes();
    let mut literals = Vec::new();
    let mut index = 0;
    let mut line = 1;
    while index < bytes.len() {
        if bytes[index..].starts_with(b"//") {
            advance_to_line_end(bytes, &mut index, &mut line);
            continue;
        }
        if bytes[index..].starts_with(b"/*") {
            advance_block_comment(bytes, &mut index, &mut line);
            continue;
        }
        if let Some((content_start, content_end, token_end)) = raw_string_bounds(bytes, index) {
            literals.push(RustStringLiteral {
                line,
                text: source[content_start..content_end].to_owned(),
            });
            advance(bytes, &mut index, token_end, &mut line);
            continue;
        }
        if let Some(token_end) = char_literal_end(bytes, index) {
            advance(bytes, &mut index, token_end, &mut line);
            continue;
        }
        if bytes[index] == b'"' {
            let literal_line = line;
            let content_start = index + 1;
            index += 1;
            while index < bytes.len() {
                match bytes[index] {
                    b'\\' => {
                        let end = (index + 2).min(bytes.len());
                        advance(bytes, &mut index, end, &mut line);
                    }
                    b'"' => {
                        literals.push(RustStringLiteral {
                            line: literal_line,
                            text: source[content_start..index].to_owned(),
                        });
                        index += 1;
                        break;
                    }
                    _ => {
                        let end = index + 1;
                        advance(bytes, &mut index, end, &mut line);
                    }
                }
            }
            continue;
        }
        let end = index + 1;
        advance(bytes, &mut index, end, &mut line);
    }
    literals
}

fn char_literal_end(bytes: &[u8], start: usize) -> Option<usize> {
    let quote = if bytes.get(start) == Some(&b'\'') {
        start
    } else if bytes.get(start..start + 2) == Some(b"b'") {
        start + 1
    } else {
        return None;
    };
    let content = quote + 1;
    let first = *bytes.get(content)?;
    let after_content = if first == b'\\' {
        match bytes.get(content + 1).copied()? {
            b'u' => {
                let close = bytes
                    .get(content + 2..)?
                    .iter()
                    .position(|byte| *byte == b'}')?;
                content + 2 + close + 1
            }
            b'x' => content + 4,
            _ => content + 2,
        }
    } else {
        content + utf8_sequence_len(first)?
    };
    (bytes.get(after_content) == Some(&b'\'')).then_some(after_content + 1)
}

const fn utf8_sequence_len(first: u8) -> Option<usize> {
    match first {
        0x00..=0x7f => Some(1),
        0xc2..=0xdf => Some(2),
        0xe0..=0xef => Some(3),
        0xf0..=0xf4 => Some(4),
        _ => None,
    }
}

fn raw_string_bounds(bytes: &[u8], start: usize) -> Option<(usize, usize, usize)> {
    let mut marker = match bytes.get(start..start + 2) {
        Some(b"br" | b"cr") => start + 2,
        _ if bytes.get(start) == Some(&b'r') => start + 1,
        _ => return None,
    };
    let hash_start = marker;
    while bytes.get(marker) == Some(&b'#') {
        marker += 1;
    }
    if bytes.get(marker) != Some(&b'"') {
        return None;
    }
    let hashes = marker - hash_start;
    let content_start = marker + 1;
    let mut content_end = content_start;
    while content_end < bytes.len() {
        if bytes[content_end] == b'"'
            && bytes.get(content_end + 1..content_end + 1 + hashes)
                == Some(&bytes[hash_start..marker])
        {
            return Some((content_start, content_end, content_end + 1 + hashes));
        }
        content_end += 1;
    }
    None
}

fn advance_to_line_end(bytes: &[u8], index: &mut usize, line: &mut usize) {
    while *index < bytes.len() {
        let end = *index + 1;
        let was_newline = bytes[*index] == b'\n';
        advance(bytes, index, end, line);
        if was_newline {
            return;
        }
    }
}

fn advance_block_comment(bytes: &[u8], index: &mut usize, line: &mut usize) {
    let mut depth = 0_u32;
    while *index < bytes.len() {
        if bytes[*index..].starts_with(b"/*") {
            depth += 1;
            advance(bytes, index, *index + 2, line);
        } else if bytes[*index..].starts_with(b"*/") {
            depth = depth.saturating_sub(1);
            advance(bytes, index, *index + 2, line);
            if depth == 0 {
                return;
            }
        } else {
            advance(bytes, index, *index + 1, line);
        }
    }
}

fn advance(bytes: &[u8], index: &mut usize, end: usize, line: &mut usize) {
    *line += bytes[*index..end]
        .iter()
        .filter(|byte| **byte == b'\n')
        .count();
    *index = end;
}

#[test]
fn product_identity_scanner_ignores_comments_tests_and_the_ordinary_verb() {
    let source = r###"
// "Forge" and "forge.example/v1" are comments.
const ORDINARY: &str = "people forge durable tools";
const QUOTE: char = '"';
const DISPLAY: &str = "Forge doctor";
const PROTOCOL: &[u8] = b"forge.example/v1";
const MARKER: &str = r#"forge:begin"#;
#[cfg(test)]
mod tests {
    const FIXTURE: &str = "Forge test fixture";
}
"###;
    let product = source_without_test_items(source);
    let observed = rust_string_literals(&product)
        .into_iter()
        .flat_map(|literal| product_identity_kinds(&literal.text))
        .collect::<BTreeSet<_>>();

    assert_eq!(
        observed,
        BTreeSet::from([
            ProductIdentityKind::DisplayName,
            ProductIdentityKind::MachineNamespace,
            ProductIdentityKind::ManagedMarker,
        ])
    );
}

#[test]
fn managed_marker_literals_have_one_non_overridable_definition_path() {
    assert!(is_product_identity_definition(
        MANAGED_MARKER_DEFINITION_PATH,
        ProductIdentityKind::ManagedMarker
    ));
    assert!(!is_product_identity_definition(
        "crates/forge-render/src/plan.rs",
        ProductIdentityKind::ManagedMarker
    ));
    assert!(!is_product_identity_definition(
        "crates/forge-core/src/branding.rs",
        ProductIdentityKind::ManagedMarker
    ));
    assert!(
        AUTHORIZED_PRODUCT_IDENTITY_USES
            .iter()
            .all(|entry| entry.kind != ProductIdentityKind::ManagedMarker)
    );
}

#[test]
fn committed_tree_has_no_tool_private_worktree_directory() -> Result<(), Box<dyn std::error::Error>>
{
    let root = repository_root()?;
    let mut violations = Vec::new();
    visit_directories(&root, &mut |path| {
        let relative = path.strip_prefix(&root).unwrap_or(path);
        if matches!(
            relative.to_str(),
            Some(".forge" | ".ai" | ".agent" | "docs/ai")
        ) {
            violations.push(relative.to_path_buf());
        }
    })?;
    assert!(
        violations.is_empty(),
        "private Forge directories must not be committed: {violations:?}"
    );
    Ok(())
}

#[test]
fn primary_verification_workflow_does_not_depend_on_forge() -> Result<(), Box<dyn std::error::Error>>
{
    let root = repository_root()?;
    let workflow = fs::read_to_string(root.join(".github/workflows/verify.yml"))?;

    assert!(!workflow.contains("cargo run -p forge-cli"));
    assert!(
        !workflow
            .lines()
            .any(|line| line.trim_start().starts_with("- run: forge "))
    );
    Ok(())
}

fn rust_source_files(root: &Path) -> Result<Vec<PathBuf>, Box<dyn std::error::Error>> {
    let mut files = Vec::new();
    visit_files(root, &mut |path| {
        if path.extension().is_some_and(|extension| extension == "rs") {
            files.push(path.to_path_buf());
        }
    })?;
    files.sort();
    Ok(files)
}

fn visit_files(
    root: &Path,
    visitor: &mut dyn FnMut(&Path),
) -> Result<(), Box<dyn std::error::Error>> {
    for entry in fs::read_dir(root)? {
        let entry = entry?;
        let file_type = entry.file_type()?;
        let path = entry.path();
        if file_type.is_dir() {
            visit_files(&path, visitor)?;
        } else if file_type.is_file() {
            visitor(&path);
        }
    }
    Ok(())
}

fn visit_directories(
    root: &Path,
    visitor: &mut dyn FnMut(&Path),
) -> Result<(), Box<dyn std::error::Error>> {
    for entry in fs::read_dir(root)? {
        let entry = entry?;
        if !entry.file_type()?.is_dir() {
            continue;
        }
        let path = entry.path();
        let name = entry.file_name();
        if name == ".git" || name == "target" {
            continue;
        }
        visitor(&path);
        visit_directories(&path, visitor)?;
    }
    Ok(())
}

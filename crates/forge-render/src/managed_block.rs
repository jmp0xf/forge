//! Deterministic Markdown managed-block parsing and merging.

use std::collections::BTreeSet;
use std::error::Error;
use std::fmt;

use forge_core::branding::BLOCK_NAMESPACE;
use forge_core::ports::Hasher;

/// Current marker schema. It evolves independently from machine-readable document schemas.
pub const MARKER_SCHEMA: u16 = 1;
const BODY_HASH_DOMAIN: &[u8] = b"forge.managed-block-body/v1";
const BEGIN_TOKEN: &str = "<!-- forge:begin";
const END_TOKEN: &str = "<!-- forge:end";

/// A generated Markdown body owned by one stable block identifier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManagedBlock<'a> {
    pub id: &'a str,
    pub body: &'a str,
}

impl ManagedBlock<'_> {
    /// Renders a complete v1 block and derives the marker hash from canonical body bytes.
    pub fn render_markdown<H>(&self, hasher: &H) -> Result<Vec<u8>, ManagedBlockError>
    where
        H: Hasher + ?Sized,
    {
        validate_block_id(self.id)?;
        let body = canonical_generated_body(self.body);
        let hash = body_digest(hasher, body.as_bytes());
        Ok(format!(
            "<!-- {namespace}:begin block={id} schema={schema} hash={hash} -->\n{body}\n<!-- {namespace}:end block={id} -->\n",
            namespace = BLOCK_NAMESPACE,
            id = self.id,
            schema = MARKER_SCHEMA,
            hash = hash,
        )
        .into_bytes())
    }
}

/// Whether merging a desired block changed the file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MergeAction {
    Create,
    Append,
    Replace,
    NoOp,
}

/// Complete deterministic postimage for one managed-block merge.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MergeOutcome {
    pub action: MergeAction,
    pub content: Vec<u8>,
}

/// A structural or ownership conflict that must be resolved before writing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ManagedBlockError {
    InvalidUtf8,
    InvalidBlockId(String),
    MalformedMarker {
        line: usize,
        detail: String,
    },
    NestedBlock {
        line: usize,
    },
    OrphanEnd {
        line: usize,
    },
    MismatchedEnd {
        line: usize,
        expected: String,
        actual: String,
    },
    UnterminatedBlock {
        id: String,
    },
    DuplicateBlock {
        id: String,
    },
    UnsupportedSchema {
        id: String,
        schema: u16,
    },
    UserEdited {
        id: String,
    },
}

impl fmt::Display for ManagedBlockError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidUtf8 => formatter.write_str("managed Markdown is not valid UTF-8"),
            Self::InvalidBlockId(id) => write!(formatter, "invalid managed block id `{id}`"),
            Self::MalformedMarker { line, detail } => {
                write!(
                    formatter,
                    "malformed managed marker at line {line}: {detail}"
                )
            }
            Self::NestedBlock { line } => {
                write!(formatter, "nested managed block begins at line {line}")
            }
            Self::OrphanEnd { line } => {
                write!(
                    formatter,
                    "managed block end marker at line {line} has no begin marker"
                )
            }
            Self::MismatchedEnd {
                line,
                expected,
                actual,
            } => write!(
                formatter,
                "managed block end marker at line {line} names `{actual}` instead of `{expected}`"
            ),
            Self::UnterminatedBlock { id } => {
                write!(formatter, "managed block `{id}` has no end marker")
            }
            Self::DuplicateBlock { id } => {
                write!(formatter, "managed block `{id}` occurs more than once")
            }
            Self::UnsupportedSchema { id, schema } => write!(
                formatter,
                "managed block `{id}` uses unsupported marker schema {schema}"
            ),
            Self::UserEdited { id } => write!(
                formatter,
                "managed block `{id}` body does not match its declared hash"
            ),
        }
    }
}

impl Error for ManagedBlockError {}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ParsedBlock {
    id: String,
    schema: u16,
    declared_hash: String,
    range_start: usize,
    range_end: usize,
    body_start: usize,
    body_end: usize,
}

#[derive(Debug)]
struct OpenBlock {
    id: String,
    schema: u16,
    declared_hash: String,
    range_start: usize,
    body_start: usize,
}

/// Merges one desired block without changing any pre-existing byte outside that block.
///
/// `force` only permits replacing the selected block when its body hash proves that it was edited.
/// Structural errors, duplicate ids, and unsupported schemas always remain fatal.
pub fn merge_markdown_block<H>(
    existing: Option<&[u8]>,
    desired: &ManagedBlock<'_>,
    hasher: &H,
    force: bool,
) -> Result<MergeOutcome, ManagedBlockError>
where
    H: Hasher + ?Sized,
{
    validate_block_id(desired.id)?;
    let rendered = desired.render_markdown(hasher)?;
    let Some(existing) = existing else {
        return Ok(MergeOutcome {
            action: MergeAction::Create,
            content: rendered,
        });
    };
    let text = std::str::from_utf8(existing).map_err(|_| ManagedBlockError::InvalidUtf8)?;
    let blocks = parse_blocks(text)?;
    let Some(current) = blocks.iter().find(|block| block.id == desired.id) else {
        let mut content = existing.to_vec();
        append_separator(&mut content);
        content.extend_from_slice(&rendered);
        return Ok(MergeOutcome {
            action: MergeAction::Append,
            content,
        });
    };

    let current_body = canonical_existing_body(&existing[current.body_start..current.body_end]);
    let actual_hash = body_digest(hasher, current_body);
    if current.declared_hash != actual_hash && !force {
        return Err(ManagedBlockError::UserEdited {
            id: current.id.clone(),
        });
    }

    let desired_body = canonical_generated_body(desired.body);
    if current.declared_hash == actual_hash && current_body == desired_body.as_bytes() {
        return Ok(MergeOutcome {
            action: MergeAction::NoOp,
            content: existing.to_vec(),
        });
    }

    let mut content = Vec::with_capacity(
        existing.len() - (current.range_end - current.range_start) + rendered.len(),
    );
    content.extend_from_slice(&existing[..current.range_start]);
    content.extend_from_slice(&rendered);
    content.extend_from_slice(&existing[current.range_end..]);
    Ok(MergeOutcome {
        action: MergeAction::Replace,
        content,
    })
}

fn parse_blocks(text: &str) -> Result<Vec<ParsedBlock>, ManagedBlockError> {
    let mut blocks = Vec::new();
    let mut ids = BTreeSet::new();
    let mut open: Option<OpenBlock> = None;
    let mut byte_offset = 0;

    for (line_index, line_with_ending) in text.split_inclusive('\n').enumerate() {
        let line_number = line_index + 1;
        let line = line_with_ending
            .strip_suffix('\n')
            .unwrap_or(line_with_ending)
            .strip_suffix('\r')
            .unwrap_or_else(|| {
                line_with_ending
                    .strip_suffix('\n')
                    .unwrap_or(line_with_ending)
            });
        let line_end = byte_offset + line_with_ending.len();
        if line.contains(BEGIN_TOKEN) {
            if open.is_some() {
                return Err(ManagedBlockError::NestedBlock { line: line_number });
            }
            let (id, schema, declared_hash) = parse_begin(line, line_number)?;
            validate_block_id(&id)?;
            if schema != MARKER_SCHEMA {
                return Err(ManagedBlockError::UnsupportedSchema { id, schema });
            }
            if !ids.insert(id.clone()) {
                return Err(ManagedBlockError::DuplicateBlock { id });
            }
            open = Some(OpenBlock {
                id,
                schema,
                declared_hash,
                range_start: byte_offset,
                body_start: line_end,
            });
        } else if line.contains(END_TOKEN) {
            let actual = parse_end(line, line_number)?;
            let Some(started) = open.take() else {
                return Err(ManagedBlockError::OrphanEnd { line: line_number });
            };
            if actual != started.id {
                return Err(ManagedBlockError::MismatchedEnd {
                    line: line_number,
                    expected: started.id,
                    actual,
                });
            }
            blocks.push(ParsedBlock {
                id: started.id,
                schema: started.schema,
                declared_hash: started.declared_hash,
                range_start: started.range_start,
                range_end: line_end,
                body_start: started.body_start,
                body_end: byte_offset,
            });
        }
        byte_offset = line_end;
    }

    if let Some(open) = open {
        return Err(ManagedBlockError::UnterminatedBlock { id: open.id });
    }
    Ok(blocks)
}

fn parse_begin(line: &str, line_number: usize) -> Result<(String, u16, String), ManagedBlockError> {
    let inside = line
        .strip_prefix("<!-- forge:begin ")
        .and_then(|value| value.strip_suffix(" -->"))
        .ok_or_else(|| malformed(line_number, "begin marker must occupy the complete line"))?;
    let mut fields = inside.split_ascii_whitespace();
    let id = parse_field(fields.next(), "block", line_number)?;
    let schema = parse_field(fields.next(), "schema", line_number)?
        .parse::<u16>()
        .map_err(|_| malformed(line_number, "schema must be an unsigned integer"))?;
    let hash = parse_field(fields.next(), "hash", line_number)?;
    if fields.next().is_some() {
        return Err(malformed(line_number, "begin marker has unknown fields"));
    }
    if hash.is_empty() {
        return Err(malformed(line_number, "hash must not be empty"));
    }
    Ok((id.to_owned(), schema, hash.to_owned()))
}

fn parse_end(line: &str, line_number: usize) -> Result<String, ManagedBlockError> {
    let inside = line
        .strip_prefix("<!-- forge:end ")
        .and_then(|value| value.strip_suffix(" -->"))
        .ok_or_else(|| malformed(line_number, "end marker must occupy the complete line"))?;
    let mut fields = inside.split_ascii_whitespace();
    let id = parse_field(fields.next(), "block", line_number)?;
    if fields.next().is_some() {
        return Err(malformed(line_number, "end marker has unknown fields"));
    }
    validate_block_id(id)?;
    Ok(id.to_owned())
}

fn parse_field<'a>(
    field: Option<&'a str>,
    name: &str,
    line_number: usize,
) -> Result<&'a str, ManagedBlockError> {
    field
        .and_then(|value| value.strip_prefix(name))
        .and_then(|value| value.strip_prefix('='))
        .filter(|value| !value.is_empty())
        .ok_or_else(|| malformed(line_number, &format!("expected `{name}=...`")))
}

fn malformed(line: usize, detail: &str) -> ManagedBlockError {
    ManagedBlockError::MalformedMarker {
        line,
        detail: detail.to_owned(),
    }
}

fn validate_block_id(id: &str) -> Result<(), ManagedBlockError> {
    let valid = !id.is_empty()
        && id.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'_' | b'.')
        })
        && id.as_bytes().first().is_some_and(u8::is_ascii_alphanumeric);
    if valid {
        Ok(())
    } else {
        Err(ManagedBlockError::InvalidBlockId(id.to_owned()))
    }
}

fn canonical_generated_body(body: &str) -> &str {
    body.trim_end_matches(['\r', '\n'])
}

fn canonical_existing_body(body: &[u8]) -> &[u8] {
    body.strip_suffix(b"\r\n")
        .or_else(|| body.strip_suffix(b"\n"))
        .unwrap_or(body)
}

fn body_digest<H>(hasher: &H, body: &[u8]) -> String
where
    H: Hasher + ?Sized,
{
    hasher.digest(&[BODY_HASH_DOMAIN, body]).into_inner()
}

fn append_separator(content: &mut Vec<u8>) {
    if content.is_empty() {
        return;
    }
    if !content.ends_with(b"\n") {
        content.push(b'\n');
    }
    if !content.ends_with(b"\n\n") {
        content.push(b'\n');
    }
}

#[cfg(test)]
mod tests {
    use forge_core::Digest;
    use forge_core::ports::Hasher;

    use super::{ManagedBlock, ManagedBlockError, MergeAction, merge_markdown_block, parse_blocks};

    #[derive(Debug)]
    struct FixtureHasher;

    impl Hasher for FixtureHasher {
        fn digest(&self, chunks: &[&[u8]]) -> Digest {
            let body = chunks.last().copied().unwrap_or_default();
            Digest::new(format!("fixture:{}", String::from_utf8_lossy(body)))
        }
    }

    #[test]
    fn rendering_is_deterministic_and_hashes_only_canonical_body() -> Result<(), ManagedBlockError>
    {
        let block = ManagedBlock {
            id: "project-index",
            body: "hello\n\n",
        };
        let first = block.render_markdown(&FixtureHasher)?;
        let second = block.render_markdown(&FixtureHasher)?;

        assert_eq!(first, second);
        assert_eq!(
            String::from_utf8(first).map_err(|_| ManagedBlockError::InvalidUtf8)?,
            "<!-- forge:begin block=project-index schema=1 hash=fixture:hello -->\nhello\n<!-- forge:end block=project-index -->\n"
        );
        Ok(())
    }

    #[test]
    fn create_then_merge_is_a_byte_identical_noop() -> Result<(), ManagedBlockError> {
        let desired = ManagedBlock {
            id: "project-index",
            body: "hello",
        };
        let created = merge_markdown_block(None, &desired, &FixtureHasher, false)?;
        let second = merge_markdown_block(
            Some(created.content.as_slice()),
            &desired,
            &FixtureHasher,
            false,
        )?;

        assert_eq!(created.action, MergeAction::Create);
        assert_eq!(second.action, MergeAction::NoOp);
        assert_eq!(second.content, created.content);
        Ok(())
    }

    #[test]
    fn append_and_replace_preserve_every_outside_byte() -> Result<(), ManagedBlockError> {
        let first = ManagedBlock {
            id: "first",
            body: "one",
        };
        let appended = merge_markdown_block(
            Some("人工前言\r\n".as_bytes()),
            &first,
            &FixtureHasher,
            false,
        )?;
        assert_eq!(appended.action, MergeAction::Append);
        assert!(appended.content.starts_with("人工前言\r\n\n".as_bytes()));

        let changed = ManagedBlock {
            id: "first",
            body: "two",
        };
        let replaced = merge_markdown_block(
            Some(appended.content.as_slice()),
            &changed,
            &FixtureHasher,
            false,
        )?;
        assert_eq!(replaced.action, MergeAction::Replace);
        assert!(replaced.content.starts_with("人工前言\r\n\n".as_bytes()));
        assert!(
            replaced
                .content
                .ends_with(b"<!-- forge:end block=first -->\n")
        );
        Ok(())
    }

    #[test]
    fn edited_body_conflicts_unless_the_selected_block_is_forced() -> Result<(), ManagedBlockError>
    {
        let desired = ManagedBlock {
            id: "project-index",
            body: "generated",
        };
        let created = merge_markdown_block(None, &desired, &FixtureHasher, false)?;
        let edited = String::from_utf8(created.content)
            .map_err(|_| ManagedBlockError::InvalidUtf8)?
            .replace("generated\n<!--", "human edit\n<!--");

        assert_eq!(
            merge_markdown_block(Some(edited.as_bytes()), &desired, &FixtureHasher, false),
            Err(ManagedBlockError::UserEdited {
                id: String::from("project-index")
            })
        );
        assert_eq!(
            merge_markdown_block(Some(edited.as_bytes()), &desired, &FixtureHasher, true)?.action,
            MergeAction::Replace
        );
        Ok(())
    }

    #[test]
    fn duplicate_nested_mismatched_and_future_markers_fail_closed() {
        let duplicate = concat!(
            "<!-- forge:begin block=x schema=1 hash=h -->\n",
            "a\n<!-- forge:end block=x -->\n",
            "<!-- forge:begin block=x schema=1 hash=h -->\n",
            "a\n<!-- forge:end block=x -->\n"
        );
        assert_eq!(
            parse_blocks(duplicate),
            Err(ManagedBlockError::DuplicateBlock {
                id: String::from("x")
            })
        );

        let nested = concat!(
            "<!-- forge:begin block=x schema=1 hash=h -->\n",
            "<!-- forge:begin block=y schema=1 hash=h -->\n"
        );
        assert_eq!(
            parse_blocks(nested),
            Err(ManagedBlockError::NestedBlock { line: 2 })
        );

        let mismatched = concat!(
            "<!-- forge:begin block=x schema=1 hash=h -->\n",
            "a\n<!-- forge:end block=y -->\n"
        );
        assert!(matches!(
            parse_blocks(mismatched),
            Err(ManagedBlockError::MismatchedEnd { .. })
        ));

        let future = concat!(
            "<!-- forge:begin block=x schema=2 hash=h -->\n",
            "a\n<!-- forge:end block=x -->\n"
        );
        assert_eq!(
            parse_blocks(future),
            Err(ManagedBlockError::UnsupportedSchema {
                id: String::from("x"),
                schema: 2
            })
        );
    }

    #[test]
    fn crlf_delimiter_does_not_create_false_user_edit_conflict() -> Result<(), ManagedBlockError> {
        let desired = ManagedBlock {
            id: "project-index",
            body: "hello",
        };
        let existing = concat!(
            "<!-- forge:begin block=project-index schema=1 hash=fixture:hello -->\r\n",
            "hello\r\n",
            "<!-- forge:end block=project-index -->\r\n"
        );
        let outcome =
            merge_markdown_block(Some(existing.as_bytes()), &desired, &FixtureHasher, false)?;

        assert_eq!(outcome.action, MergeAction::NoOp);
        assert_eq!(outcome.content, existing.as_bytes());
        Ok(())
    }
}

//! Deterministic managed-block parsing and merging.

use std::borrow::Cow;
use std::collections::BTreeSet;
use std::error::Error;
use std::fmt;

use forge_core::ports::Hasher;

/// Current marker schema. It evolves independently from machine-readable document schemas.
pub const MARKER_SCHEMA: u16 = 1;
const BODY_HASH_DOMAIN: &[u8] = b"forge.managed-block-body/v1";
const BEGIN_MARKER_TOKEN: &str = "forge:begin";
const END_MARKER_TOKEN: &str = "forge:end";
const BLOCK_FIELD: &str = "block";
const SCHEMA_FIELD: &str = "schema";
const HASH_FIELD: &str = "hash";

#[derive(Debug, Clone, Copy)]
struct CommentSyntax {
    prefix: &'static str,
    suffix: &'static str,
}

/// Comment syntax used by one managed file type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ManagedBlockSyntax {
    Markdown,
    HashComment,
}

/// Line ending used for newly rendered managed bytes.
///
/// Existing uniform files take precedence during a merge. This value is therefore the explicit
/// fallback for a new file or for existing content whose style cannot be determined reliably.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum LineEnding {
    Lf,
    CrLf,
}

impl LineEnding {
    const fn bytes(self) -> &'static [u8] {
        match self {
            Self::Lf => b"\n",
            Self::CrLf => b"\r\n",
        }
    }
}

impl ManagedBlockSyntax {
    const fn comment(self) -> CommentSyntax {
        match self {
            Self::Markdown => CommentSyntax {
                prefix: "<!-- ",
                suffix: " -->",
            },
            Self::HashComment => CommentSyntax {
                prefix: "# ",
                suffix: "",
            },
        }
    }

    fn contains_token(self, line: &str, token: &str) -> bool {
        let comment = self.comment();
        line.match_indices(comment.prefix)
            .any(|(start, _)| line[start + comment.prefix.len()..].starts_with(token))
    }

    fn strip_marker<'a>(self, line: &'a str, token: &str) -> Option<&'a str> {
        let comment = self.comment();
        line.strip_prefix(comment.prefix)?
            .strip_suffix(comment.suffix)?
            .strip_prefix(token)?
            .strip_prefix(' ')
    }

    fn strip_marker_bytes<'a>(self, line: &'a [u8], token: &str) -> Option<&'a [u8]> {
        let comment = self.comment();
        line.strip_prefix(comment.prefix.as_bytes())?
            .strip_suffix(comment.suffix.as_bytes())?
            .strip_prefix(token.as_bytes())?
            .strip_prefix(b" ")
    }
}

/// A generated body owned by one stable block identifier.
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
        self.render(ManagedBlockSyntax::Markdown, hasher)
    }

    /// Renders a complete hash-comment v1 block for runner/config file formats.
    pub fn render_hash_comment<H>(&self, hasher: &H) -> Result<Vec<u8>, ManagedBlockError>
    where
        H: Hasher + ?Sized,
    {
        self.render(ManagedBlockSyntax::HashComment, hasher)
    }

    /// Renders a complete v1 block and derives the marker hash from canonical body bytes.
    pub fn render<H>(
        &self,
        syntax: ManagedBlockSyntax,
        hasher: &H,
    ) -> Result<Vec<u8>, ManagedBlockError>
    where
        H: Hasher + ?Sized,
    {
        self.render_with_line_ending(syntax, LineEnding::Lf, hasher)
    }

    /// Renders a complete v1 block using an explicit line ending.
    pub fn render_with_line_ending<H>(
        &self,
        syntax: ManagedBlockSyntax,
        line_ending: LineEnding,
        hasher: &H,
    ) -> Result<Vec<u8>, ManagedBlockError>
    where
        H: Hasher + ?Sized,
    {
        self.render_complete(syntax, line_ending, true, hasher)
    }

    fn render_complete<H>(
        &self,
        syntax: ManagedBlockSyntax,
        line_ending: LineEnding,
        trailing_line_ending: bool,
        hasher: &H,
    ) -> Result<Vec<u8>, ManagedBlockError>
    where
        H: Hasher + ?Sized,
    {
        validate_block_id(self.id)?;
        let body = canonical_generated_body(self.body);
        let hash = body_digest(hasher, body.as_bytes());
        let begin = render_begin_marker(syntax, self.id, &hash);
        let end = render_end_marker(syntax, self.id);
        let mut rendered = Vec::with_capacity(
            begin.len() + end.len() + body.len() + (3 * line_ending.bytes().len()),
        );
        rendered.extend_from_slice(begin.as_bytes());
        rendered.extend_from_slice(line_ending.bytes());
        append_canonical_body(&mut rendered, body.as_bytes(), line_ending);
        rendered.extend_from_slice(line_ending.bytes());
        rendered.extend_from_slice(end.as_bytes());
        if trailing_line_ending {
            rendered.extend_from_slice(line_ending.bytes());
        }
        Ok(rendered)
    }
}

fn render_begin_marker(syntax: ManagedBlockSyntax, id: &str, hash: &str) -> String {
    let comment = syntax.comment();
    format!(
        "{prefix}{BEGIN_MARKER_TOKEN} {BLOCK_FIELD}={id} {SCHEMA_FIELD}={MARKER_SCHEMA} {HASH_FIELD}={hash}{suffix}",
        prefix = comment.prefix,
        suffix = comment.suffix,
    )
}

fn render_end_marker(syntax: ManagedBlockSyntax, id: &str) -> String {
    let comment = syntax.comment();
    format!(
        "{prefix}{END_MARKER_TOKEN} {BLOCK_FIELD}={id}{suffix}",
        prefix = comment.prefix,
        suffix = comment.suffix,
    )
}

/// Returns whether a value contains a reserved managed-marker directive.
///
/// Runner renderers use this before quoting values because marker directives are structural,
/// not ordinary user-controlled text.
#[must_use]
pub(crate) fn contains_managed_marker_token(value: &str) -> bool {
    value.contains(BEGIN_MARKER_TOKEN) || value.contains(END_MARKER_TOKEN)
}

/// Recognizes lexical ownership without accepting a similar block id.
///
/// This intentionally does not validate the remaining fields. A malformed or future marker for
/// the selected block must proceed to the full parser and fail closed instead of making Forge
/// treat an owned file as human-owned.
#[must_use]
pub(crate) fn contains_managed_block_begin(
    bytes: &[u8],
    syntax: ManagedBlockSyntax,
    block_id: &str,
) -> bool {
    bytes.split(|byte| *byte == b'\n').any(|line| {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        let Some(fields) = syntax.strip_marker_bytes(line, BEGIN_MARKER_TOKEN) else {
            return false;
        };
        first_field_value(fields, BLOCK_FIELD).is_some_and(|id| id == block_id.as_bytes())
    })
}

fn first_field_value<'a>(fields: &'a [u8], name: &str) -> Option<&'a [u8]> {
    let value = fields.strip_prefix(name.as_bytes())?.strip_prefix(b"=")?;
    let end = value
        .iter()
        .position(u8::is_ascii_whitespace)
        .unwrap_or(value.len());
    Some(&value[..end])
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
    merge_managed_block(
        existing,
        desired,
        ManagedBlockSyntax::Markdown,
        hasher,
        force,
    )
}

/// Merges one desired block using the selected comment syntax.
pub fn merge_managed_block<H>(
    existing: Option<&[u8]>,
    desired: &ManagedBlock<'_>,
    syntax: ManagedBlockSyntax,
    hasher: &H,
    force: bool,
) -> Result<MergeOutcome, ManagedBlockError>
where
    H: Hasher + ?Sized,
{
    merge_managed_block_with_line_ending(existing, desired, syntax, LineEnding::Lf, hasher, force)
}

/// Merges one desired block with an explicit fallback line ending.
///
/// A uniform existing file or managed block always keeps its own line-ending style. The fallback
/// is used only when creating content or when the existing style is not reliably identifiable.
pub fn merge_managed_block_with_line_ending<H>(
    existing: Option<&[u8]>,
    desired: &ManagedBlock<'_>,
    syntax: ManagedBlockSyntax,
    fallback_line_ending: LineEnding,
    hasher: &H,
    force: bool,
) -> Result<MergeOutcome, ManagedBlockError>
where
    H: Hasher + ?Sized,
{
    validate_block_id(desired.id)?;
    let Some(existing) = existing else {
        return Ok(MergeOutcome {
            action: MergeAction::Create,
            content: desired.render_complete(syntax, fallback_line_ending, true, hasher)?,
        });
    };
    let text = std::str::from_utf8(existing).map_err(|_| ManagedBlockError::InvalidUtf8)?;
    let blocks = parse_blocks(text, syntax)?;
    let Some(current) = blocks.iter().find(|block| block.id == desired.id) else {
        let line_ending = uniform_line_ending(existing).unwrap_or(fallback_line_ending);
        let preserve_trailing_line_ending = existing.is_empty() || existing.ends_with(b"\n");
        let mut content = existing.to_vec();
        append_separator(&mut content, line_ending);
        content.extend_from_slice(&desired.render_complete(
            syntax,
            line_ending,
            preserve_trailing_line_ending,
            hasher,
        )?);
        return Ok(MergeOutcome {
            action: MergeAction::Append,
            content,
        });
    };

    let current_body = canonical_existing_body(&existing[current.body_start..current.body_end]);
    let actual_hash = body_digest(hasher, current_body.as_ref());
    if current.declared_hash != actual_hash && !force {
        return Err(ManagedBlockError::UserEdited {
            id: current.id.clone(),
        });
    }

    let desired_body = canonical_generated_body(desired.body);
    if current.declared_hash == actual_hash && current_body.as_ref() == desired_body.as_bytes() {
        return Ok(MergeOutcome {
            action: MergeAction::NoOp,
            content: existing.to_vec(),
        });
    }

    let line_ending = uniform_line_ending(&existing[current.range_start..current.range_end])
        .or_else(|| uniform_line_ending(existing))
        .unwrap_or(fallback_line_ending);
    let preserve_trailing_line_ending =
        current.range_end < existing.len() || existing.ends_with(b"\n");
    let rendered =
        desired.render_complete(syntax, line_ending, preserve_trailing_line_ending, hasher)?;
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

fn parse_blocks(
    text: &str,
    syntax: ManagedBlockSyntax,
) -> Result<Vec<ParsedBlock>, ManagedBlockError> {
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
        if syntax.contains_token(line, BEGIN_MARKER_TOKEN) {
            if open.is_some() {
                return Err(ManagedBlockError::NestedBlock { line: line_number });
            }
            let (id, schema, declared_hash) = parse_begin(line, line_number, syntax)?;
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
        } else if syntax.contains_token(line, END_MARKER_TOKEN) {
            let actual = parse_end(line, line_number, syntax)?;
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

fn parse_begin(
    line: &str,
    line_number: usize,
    syntax: ManagedBlockSyntax,
) -> Result<(String, u16, String), ManagedBlockError> {
    let inside = syntax
        .strip_marker(line, BEGIN_MARKER_TOKEN)
        .ok_or_else(|| malformed(line_number, "begin marker must occupy the complete line"))?;
    let mut fields = inside.split_ascii_whitespace();
    let id = parse_field(fields.next(), BLOCK_FIELD, line_number)?;
    let schema = parse_field(fields.next(), SCHEMA_FIELD, line_number)?
        .parse::<u16>()
        .map_err(|_| malformed(line_number, "schema must be an unsigned integer"))?;
    let hash = parse_field(fields.next(), HASH_FIELD, line_number)?;
    if fields.next().is_some() {
        return Err(malformed(line_number, "begin marker has unknown fields"));
    }
    if hash.is_empty() {
        return Err(malformed(line_number, "hash must not be empty"));
    }
    Ok((id.to_owned(), schema, hash.to_owned()))
}

fn parse_end(
    line: &str,
    line_number: usize,
    syntax: ManagedBlockSyntax,
) -> Result<String, ManagedBlockError> {
    let inside = syntax
        .strip_marker(line, END_MARKER_TOKEN)
        .ok_or_else(|| malformed(line_number, "end marker must occupy the complete line"))?;
    let mut fields = inside.split_ascii_whitespace();
    let id = parse_field(fields.next(), BLOCK_FIELD, line_number)?;
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

fn canonical_generated_body(body: &str) -> Cow<'_, str> {
    let body = body.trim_end_matches(['\r', '\n']);
    if body.contains("\r\n") {
        Cow::Owned(body.replace("\r\n", "\n"))
    } else {
        Cow::Borrowed(body)
    }
}

fn canonical_existing_body(body: &[u8]) -> Cow<'_, [u8]> {
    let body = body
        .strip_suffix(b"\r\n")
        .or_else(|| body.strip_suffix(b"\n"))
        .unwrap_or(body);
    if body.windows(2).any(|window| window == b"\r\n") {
        let mut canonical = Vec::with_capacity(body.len());
        let mut remaining = body;
        while let Some(index) = remaining.windows(2).position(|window| window == b"\r\n") {
            canonical.extend_from_slice(&remaining[..index]);
            canonical.push(b'\n');
            remaining = &remaining[index + 2..];
        }
        canonical.extend_from_slice(remaining);
        Cow::Owned(canonical)
    } else {
        Cow::Borrowed(body)
    }
}

fn body_digest<H>(hasher: &H, body: &[u8]) -> String
where
    H: Hasher + ?Sized,
{
    hasher.digest(&[BODY_HASH_DOMAIN, body]).into_inner()
}

fn append_canonical_body(content: &mut Vec<u8>, body: &[u8], line_ending: LineEnding) {
    let mut remaining = body;
    while let Some(index) = remaining.iter().position(|byte| *byte == b'\n') {
        content.extend_from_slice(&remaining[..index]);
        content.extend_from_slice(line_ending.bytes());
        remaining = &remaining[index + 1..];
    }
    content.extend_from_slice(remaining);
}

fn uniform_line_ending(content: &[u8]) -> Option<LineEnding> {
    let mut observed = None;
    for (index, byte) in content.iter().enumerate() {
        if *byte != b'\n' {
            continue;
        }
        let current = if index > 0 && content[index - 1] == b'\r' {
            LineEnding::CrLf
        } else {
            LineEnding::Lf
        };
        if observed.is_some_and(|line_ending| line_ending != current) {
            return None;
        }
        observed = Some(current);
    }
    observed
}

fn append_separator(content: &mut Vec<u8>, line_ending: LineEnding) {
    if content.is_empty() {
        return;
    }
    let separator = line_ending.bytes();
    if !content.ends_with(separator) {
        content.extend_from_slice(separator);
    }
    let has_blank_separator = content
        .strip_suffix(separator)
        .is_some_and(|prefix| prefix.ends_with(separator));
    if !has_blank_separator {
        content.extend_from_slice(separator);
    }
}

#[cfg(test)]
mod tests {
    use forge_core::Digest;
    use forge_core::ports::Hasher;

    use super::{
        LineEnding, ManagedBlock, ManagedBlockError, ManagedBlockSyntax, MergeAction,
        contains_managed_block_begin, contains_managed_marker_token, merge_managed_block,
        merge_managed_block_with_line_ending, merge_markdown_block, parse_blocks,
    };

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
    fn crlf_append_and_replace_keep_one_uniform_file_style() -> Result<(), ManagedBlockError> {
        let human_prefix = "人工前言\r\n保持原样\r\n";
        let appended = merge_markdown_block(
            Some(human_prefix.as_bytes()),
            &ManagedBlock {
                id: "first",
                body: "one",
            },
            &FixtureHasher,
            false,
        )?;
        assert_eq!(appended.action, MergeAction::Append);
        assert_eq!(
            appended.content,
            concat!(
                "人工前言\r\n",
                "保持原样\r\n",
                "\r\n",
                "<!-- forge:begin block=first schema=1 hash=fixture:one -->\r\n",
                "one\r\n",
                "<!-- forge:end block=first -->\r\n",
            )
            .as_bytes()
        );
        assert_has_only_crlf(&appended.content);

        let replaced = merge_markdown_block(
            Some(appended.content.as_slice()),
            &ManagedBlock {
                id: "first",
                body: "two",
            },
            &FixtureHasher,
            false,
        )?;
        assert_eq!(replaced.action, MergeAction::Replace);
        assert_eq!(
            replaced.content,
            concat!(
                "人工前言\r\n",
                "保持原样\r\n",
                "\r\n",
                "<!-- forge:begin block=first schema=1 hash=fixture:two -->\r\n",
                "two\r\n",
                "<!-- forge:end block=first -->\r\n",
            )
            .as_bytes()
        );
        assert_has_only_crlf(&replaced.content);
        Ok(())
    }

    #[test]
    fn canonical_body_hash_is_stable_across_lf_and_crlf() -> Result<(), ManagedBlockError> {
        struct HexHasher;

        impl Hasher for HexHasher {
            fn digest(&self, chunks: &[&[u8]]) -> Digest {
                let body = chunks.last().copied().unwrap_or_default();
                const HEX: &[u8; 16] = b"0123456789abcdef";
                let mut encoded = String::with_capacity(body.len().saturating_mul(2));
                for byte in body {
                    encoded.push(char::from(HEX[usize::from(byte >> 4)]));
                    encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
                }
                Digest::new(format!("fixture:{encoded}"))
            }
        }

        let desired = ManagedBlock {
            id: "project-index",
            body: "first\nsecond",
        };
        let lf = desired.render_markdown(&HexHasher)?;
        let crlf = lf.split(|byte| *byte == b'\n').enumerate().fold(
            Vec::new(),
            |mut converted, (index, line)| {
                if index > 0 {
                    converted.extend_from_slice(b"\r\n");
                }
                converted.extend_from_slice(line);
                converted
            },
        );
        let outcome = merge_markdown_block(Some(&crlf), &desired, &HexHasher, false)?;

        assert_eq!(outcome.action, MergeAction::NoOp);
        assert_eq!(outcome.content, crlf);
        assert_has_only_crlf(&outcome.content);
        Ok(())
    }

    #[test]
    fn append_and_replace_preserve_the_existing_tail_newline_property()
    -> Result<(), ManagedBlockError> {
        let appended = merge_markdown_block(
            Some(b"human text"),
            &ManagedBlock {
                id: "project-index",
                body: "generated",
            },
            &FixtureHasher,
            false,
        )?;
        assert_eq!(appended.action, MergeAction::Append);
        assert!(!appended.content.ends_with(b"\n"));

        let created = merge_managed_block_with_line_ending(
            None,
            &ManagedBlock {
                id: "project-index",
                body: "old",
            },
            ManagedBlockSyntax::Markdown,
            LineEnding::CrLf,
            &FixtureHasher,
            false,
        )?;
        let mut without_tail = created.content;
        without_tail.truncate(without_tail.len() - 2);
        let replaced = merge_markdown_block(
            Some(&without_tail),
            &ManagedBlock {
                id: "project-index",
                body: "new",
            },
            &FixtureHasher,
            false,
        )?;
        assert_eq!(replaced.action, MergeAction::Replace);
        assert!(!replaced.content.ends_with(b"\n"));
        assert_has_only_crlf(&replaced.content);
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
            parse_blocks(duplicate, ManagedBlockSyntax::Markdown),
            Err(ManagedBlockError::DuplicateBlock {
                id: String::from("x")
            })
        );

        let nested = concat!(
            "<!-- forge:begin block=x schema=1 hash=h -->\n",
            "<!-- forge:begin block=y schema=1 hash=h -->\n"
        );
        assert_eq!(
            parse_blocks(nested, ManagedBlockSyntax::Markdown),
            Err(ManagedBlockError::NestedBlock { line: 2 })
        );

        let mismatched = concat!(
            "<!-- forge:begin block=x schema=1 hash=h -->\n",
            "a\n<!-- forge:end block=y -->\n"
        );
        assert!(matches!(
            parse_blocks(mismatched, ManagedBlockSyntax::Markdown),
            Err(ManagedBlockError::MismatchedEnd { .. })
        ));

        let future = concat!(
            "<!-- forge:begin block=x schema=2 hash=h -->\n",
            "a\n<!-- forge:end block=x -->\n"
        );
        assert_eq!(
            parse_blocks(future, ManagedBlockSyntax::Markdown),
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

    #[test]
    fn hash_comment_blocks_are_idempotent_and_preserve_brownfield_bytes()
    -> Result<(), ManagedBlockError> {
        struct StaticHasher;

        impl Hasher for StaticHasher {
            fn digest(&self, _chunks: &[&[u8]]) -> Digest {
                Digest::new("fixture:hash")
            }
        }

        let desired = ManagedBlock {
            id: "runner-make-verify",
            body: ".PHONY: verify\nverify:\n\t'cargo' 'test'",
        };
        let created = merge_managed_block(
            None,
            &desired,
            ManagedBlockSyntax::HashComment,
            &StaticHasher,
            false,
        )?;
        assert_eq!(
            created.content,
            b"# forge:begin block=runner-make-verify schema=1 hash=fixture:hash\n.PHONY: verify\nverify:\n\t'cargo' 'test'\n# forge:end block=runner-make-verify\n"
        );

        let mut brownfield = b"# human-owned prefix\r\n".to_vec();
        brownfield.extend_from_slice(&created.content);
        brownfield.extend_from_slice(b"# human-owned suffix\r\n");
        let noop = merge_managed_block(
            Some(&brownfield),
            &desired,
            ManagedBlockSyntax::HashComment,
            &StaticHasher,
            false,
        )?;

        assert_eq!(noop.action, MergeAction::NoOp);
        assert_eq!(noop.content, brownfield);
        Ok(())
    }

    #[test]
    fn lexical_begin_recognition_preserves_ownership_until_full_validation() {
        let malformed_owned =
            b"# forge:begin block=runner-make-verify schema=future without-a-hash\r\n";
        assert!(contains_managed_block_begin(
            malformed_owned,
            ManagedBlockSyntax::HashComment,
            "runner-make-verify"
        ));
        assert!(!contains_managed_block_begin(
            malformed_owned,
            ManagedBlockSyntax::HashComment,
            "runner-make-verify-old"
        ));
        assert!(!contains_managed_block_begin(
            b"# forge:begin block=runner-make-verify-old schema=1 hash=h\n",
            ManagedBlockSyntax::HashComment,
            "runner-make-verify"
        ));
    }

    #[test]
    fn reserved_marker_tokens_are_recognized_without_comment_syntax() {
        assert!(contains_managed_marker_token("prefix forge:begin suffix"));
        assert!(contains_managed_marker_token("prefix forge:end suffix"));
        assert!(!contains_managed_marker_token("forge begin"));
    }

    fn assert_has_only_crlf(content: &[u8]) {
        for (index, byte) in content.iter().enumerate() {
            if *byte == b'\n' {
                assert!(index > 0 && content[index - 1] == b'\r');
            }
        }
    }
}

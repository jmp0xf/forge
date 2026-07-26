//! Managed-block rendering bootstrap.

use forge_core::branding::BLOCK_NAMESPACE;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManagedBlock<'a> {
    pub id: &'a str,
    pub schema: u16,
    pub declared_hash: &'a str,
    pub body: &'a str,
}

impl ManagedBlock<'_> {
    #[must_use]
    pub fn render_markdown(&self) -> String {
        format!(
            "<!-- {ns}:begin block={id} schema={schema} hash={hash} -->\n{body}\n<!-- {ns}:end block={id} -->\n",
            ns = BLOCK_NAMESPACE,
            id = self.id,
            schema = self.schema,
            hash = self.declared_hash,
            body = self.body.trim_end(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::ManagedBlock;

    #[test]
    fn rendering_is_deterministic() {
        let block = ManagedBlock {
            id: "project-index",
            schema: 1,
            declared_hash: "blake3:example",
            body: "hello",
        };
        let first = block.render_markdown();
        let second = block.render_markdown();
        assert_eq!(first, second);
        assert!(first.contains("forge:begin"));
    }
}

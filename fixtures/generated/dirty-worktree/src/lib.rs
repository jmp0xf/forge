pub fn fixture_name() -> &'static str {
    "dirty-worktree"
}

#[cfg(test)]
mod tests {
    #[test]
    fn project_command_remains_independent() {
        assert_eq!(super::fixture_name(), "dirty-worktree");
    }
}

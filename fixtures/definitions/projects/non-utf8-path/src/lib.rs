pub fn fixture_name() -> &'static str {
    "non-utf8-path"
}

#[cfg(test)]
mod tests {
    #[test]
    fn project_command_remains_independent() {
        assert_eq!(super::fixture_name(), "non-utf8-path");
    }
}

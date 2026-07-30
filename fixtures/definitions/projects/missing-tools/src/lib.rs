pub fn project_native_check() -> &'static str {
    "independent of the unavailable configured command"
}

#[cfg(test)]
mod tests {
    #[test]
    fn project_keeps_a_native_test_path() {
        assert_eq!(
            super::project_native_check(),
            "independent of the unavailable configured command"
        );
    }
}

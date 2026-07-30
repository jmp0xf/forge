pub fn rust_language() -> &'static str {
    "rust"
}

#[cfg(test)]
mod tests {
    #[test]
    fn identifies_rust() {
        assert_eq!(super::rust_language(), "rust");
    }
}

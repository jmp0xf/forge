#[cfg(feature = "greeting")]
pub fn greeting() -> &'static str {
    "hello from rust"
}

#[cfg(test)]
mod tests {
    #[test]
    fn default_feature_is_enabled() {
        assert_eq!(super::greeting(), "hello from rust");
    }
}

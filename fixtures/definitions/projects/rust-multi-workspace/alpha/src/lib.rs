pub fn name() -> &'static str {
    "alpha"
}

#[cfg(test)]
mod tests {
    #[test]
    fn identifies_alpha_workspace() {
        assert_eq!(super::name(), "alpha");
    }
}

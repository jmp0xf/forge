pub fn name() -> &'static str {
    "beta"
}

#[cfg(test)]
mod tests {
    #[test]
    fn identifies_beta_workspace() {
        assert_eq!(super::name(), "beta");
    }
}

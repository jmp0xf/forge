pub fn answer() -> u8 {
    fixture_rust_no_lock_support::answer()
}

#[cfg(test)]
mod tests {
    #[test]
    fn returns_the_answer() {
        assert_eq!(super::answer(), 42);
    }
}

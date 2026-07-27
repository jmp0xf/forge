pub fn answer() -> u8 {
    42
}

#[cfg(test)]
mod tests {
    #[test]
    fn returns_the_answer() {
        assert_eq!(super::answer(), 42);
    }
}

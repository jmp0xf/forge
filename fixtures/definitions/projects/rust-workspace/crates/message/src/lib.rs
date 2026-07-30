pub fn message() -> &'static str {
    "hello"
}

#[cfg(test)]
mod tests {
    #[test]
    fn returns_message() {
        assert_eq!(super::message(), "hello");
    }
}

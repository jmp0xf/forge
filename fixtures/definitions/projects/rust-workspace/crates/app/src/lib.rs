pub fn greeting() -> String {
    format!("{} from app", fixture_rust_workspace_message::message())
}

#[cfg(test)]
mod tests {
    #[test]
    fn uses_the_path_dependency() {
        assert_eq!(super::greeting(), "hello from app");
    }
}

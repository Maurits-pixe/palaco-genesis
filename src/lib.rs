pub fn healthcheck() -> &'static str {
    "ok"
}

#[cfg(test)]
mod tests {
    use super::healthcheck;

    #[test]
    fn healthcheck_returns_ok() {
        assert_eq!(healthcheck(), "ok");
    }
}

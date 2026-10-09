const DEFAULT_API: &str = "https://api.c2pa.design/v1";

pub fn value(name: &str) -> Option<String> {
    std::env::var(name)
        .ok()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
}

pub fn api_key() -> Option<String> {
    first_set(value, &["C2PA_API_KEY", "C2PA_DESIGN_API_KEY"])
}

pub fn api_base() -> String {
    first_set(value, &["C2PA_API_BASE", "C2PA_DESIGN_API_URL"])
        .unwrap_or_else(|| DEFAULT_API.to_string())
}

fn first_set(lookup: impl Fn(&str) -> Option<String>, names: &[&str]) -> Option<String> {
    names.iter().find_map(|name| lookup(name))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lookup<'a>(set: &'a [(&str, &str)]) -> impl Fn(&str) -> Option<String> + 'a {
        move |name| {
            set.iter()
                .find(|(key, _)| *key == name)
                .map(|(_, v)| v.to_string())
        }
    }

    #[test]
    fn the_current_name_wins_over_the_deprecated_one() {
        let set = [("C2PA_API_KEY", "new"), ("C2PA_DESIGN_API_KEY", "old")];
        assert_eq!(
            first_set(lookup(&set), &["C2PA_API_KEY", "C2PA_DESIGN_API_KEY"]).as_deref(),
            Some("new")
        );
    }

    #[test]
    fn the_deprecated_name_is_a_fallback() {
        let set = [("C2PA_DESIGN_API_URL", "http://old")];
        assert_eq!(
            first_set(lookup(&set), &["C2PA_API_BASE", "C2PA_DESIGN_API_URL"]).as_deref(),
            Some("http://old")
        );
        assert_eq!(first_set(lookup(&[]), &["C2PA_API_BASE"]), None);
    }

    #[test]
    fn blank_values_count_as_unset() {
        assert_eq!(value("C2PA_CHECK_TEST_SURELY_UNSET_VARIABLE"), None);
    }
}

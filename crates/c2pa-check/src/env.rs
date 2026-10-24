use std::sync::OnceLock;

const DEFAULT_API: &str = "https://api.c2pa.design/v1";

static CONFIG_ORGANIZATION: OnceLock<Option<String>> = OnceLock::new();

pub fn value(name: &str) -> Option<String> {
    std::env::var(name)
        .ok()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
}

pub fn api_key() -> Option<String> {
    first_set(value, &["C2PA_API_KEY", "C2PA_DESIGN_API_KEY"]).or_else(|| {
        let saved = std::fs::read_to_string(credentials_path()?).ok()?;
        pick_key(&saved, organization().as_deref())
    })
}

pub fn set_config_organization(slug: Option<String>) {
    let _ = CONFIG_ORGANIZATION.set(
        slug.map(|slug| slug.trim().to_string())
            .filter(|slug| !slug.is_empty()),
    );
}

pub fn organization() -> Option<String> {
    value("C2PA_ORG").or_else(|| CONFIG_ORGANIZATION.get().cloned().flatten())
}

pub fn parse_credentials(text: &str) -> impl Iterator<Item = (&str, &str)> {
    text.lines()
        .map(|line| line.split_once(':').unwrap_or(("", line)))
        .map(|(organization, key)| (organization.trim(), key.trim()))
        .filter(|(_, key)| !key.is_empty())
}

fn pick_key(text: &str, organization: Option<&str>) -> Option<String> {
    let mut keys = parse_credentials(text);
    match organization {
        Some(wanted) => keys.find(|(id, _)| *id == wanted),
        None => keys.next(),
    }
    .map(|(_, key)| key.to_string())
}

pub fn config_dir() -> Option<std::path::PathBuf> {
    std::env::var_os("XDG_CONFIG_HOME")
        .map(std::path::PathBuf::from)
        .or_else(|| {
            std::env::var_os("HOME").map(|home| std::path::PathBuf::from(home).join(".config"))
        })
        .map(|base| base.join("c2pa-check"))
}

pub fn credentials_path() -> Option<std::path::PathBuf> {
    config_dir().map(|dir| dir.join("credentials"))
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
    fn a_key_is_picked_by_organization_and_the_latest_login_is_the_default() {
        let saved = "drc:c2pa_live_d\n\nacme : c2pa_live_a \nc2pa_live_legacy\n";

        assert_eq!(pick_key(saved, None).as_deref(), Some("c2pa_live_d"));
        assert_eq!(
            pick_key(saved, Some("acme")).as_deref(),
            Some("c2pa_live_a")
        );
        assert_eq!(pick_key(saved, Some("other")), None);
        assert_eq!(
            pick_key("c2pa_live_legacy\n", None).as_deref(),
            Some("c2pa_live_legacy")
        );
        assert_eq!(pick_key("", None), None);
    }

    #[test]
    fn blank_values_count_as_unset() {
        assert_eq!(value("C2PA_CHECK_TEST_SURELY_UNSET_VARIABLE"), None);
    }
}

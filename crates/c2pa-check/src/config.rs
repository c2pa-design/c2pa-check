use std::path::{Path, PathBuf};

use serde::Deserialize;
use serde_json::Value;

use crate::{Expect, Metric};

pub const DEFAULT_PATH: &str = "c2pa.json";
const MAX_PROJECT_CHARS: usize = 64;

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(rename = "$schema", default)]
    _schema: Option<String>,
    #[serde(default)]
    pub project: Option<String>,
    #[serde(default)]
    pub organization: Option<String>,
    #[serde(default)]
    pub checks: Vec<Check>,
    #[serde(default)]
    pub webhooks: Vec<Webhook>,
    #[serde(default)]
    pub monitors: Vec<Value>,
    #[serde(default)]
    pub domains: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Check {
    pub name: String,
    pub paths: Vec<String>,
    #[serde(default)]
    pub coverage: Option<f64>,
    #[serde(default)]
    pub coverage_metric: Option<Metric>,
    #[serde(default)]
    pub expect: Option<Expect>,
    #[serde(default)]
    pub baseline: Option<PathBuf>,
    #[serde(default)]
    pub git_tracked: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Webhook {
    pub url: String,
    pub events: Vec<String>,
}

pub fn load(explicit: Option<&Path>) -> anyhow::Result<Option<Config>> {
    let path = explicit.unwrap_or(Path::new(DEFAULT_PATH));
    let text = match std::fs::read_to_string(path) {
        Ok(text) => text,
        Err(err) if explicit.is_none() && err.kind() == std::io::ErrorKind::NotFound => {
            return Ok(None)
        }
        Err(err) => anyhow::bail!("reading {}: {err}", path.display()),
    };

    let config: Config =
        serde_json::from_str(&text).map_err(|err| anyhow::anyhow!("{}: {err}", path.display()))?;
    if let Some(project) = &config.project {
        let length = project.trim().chars().count();
        if length == 0 || length > MAX_PROJECT_CHARS {
            anyhow::bail!(
                "{}: project must be 1 to {MAX_PROJECT_CHARS} characters",
                path.display()
            );
        }
    }

    Ok(Some(config))
}

pub fn project(explicit: Option<&Path>) -> anyhow::Result<Option<String>> {
    Ok(load(explicit)?
        .and_then(|config| config.project)
        .map(|name| name.trim().to_string()))
}

pub fn require(explicit: Option<&Path>) -> anyhow::Result<Config> {
    load(explicit)?
        .ok_or_else(|| anyhow::anyhow!("no {DEFAULT_PATH} here; write one or pass --config PATH"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_config_parses_and_a_typo_is_an_error_not_a_silent_default() {
        let good: Config = serde_json::from_str(
            r#"{"$schema":"https://c2pa.design/schemas/c2pa.v1.json",
                "project":"Storefront","organization":"acme",
                "checks":[{"name":"sources","paths":["design/**/*.png"],"coverage":39,"coverage_metric":"traced","expect":"present"}],
                "webhooks":[{"url":"https://h/hook","events":["asset.lost"]}],
                "monitors":[{"name":"CDN"}],"domains":["example.com"]}"#,
        )
        .unwrap();
        let typo =
            serde_json::from_str::<Config>(r#"{"checks":[{"name":"a","paths":[],"covrage":1}]}"#);

        assert_eq!(good.checks[0].coverage, Some(39.0));
        assert_eq!(good.checks[0].coverage_metric, Some(Metric::Traced));
        assert_eq!(good.project.as_deref(), Some("Storefront"));
        assert_eq!(good.organization.as_deref(), Some("acme"));
        assert!(serde_json::from_str::<Config>(r#"{"projekt":"a"}"#).is_err());
        assert!(serde_json::from_str::<Config>(
            r#"{"checks":[{"name":"a","paths":[],"coverage_metric":"signed"}]}"#
        )
        .is_err());
        assert_eq!(good.checks[0].expect, Some(Expect::Present));
        assert_eq!(good.domains, ["example.com"]);
        assert!(typo.is_err());
        assert!(load(None).unwrap().is_none() || Path::new(DEFAULT_PATH).exists());
        assert!(load(Some(Path::new("/nonexistent/c2pa.json"))).is_err());
    }

    #[test]
    fn a_project_name_is_trimmed_and_an_empty_or_long_one_is_refused() {
        let dir = std::env::temp_dir().join(format!("c2pa-check-project-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let write = |name: &str, project: &str| {
            let path = dir.join(name);
            std::fs::write(&path, serde_json::json!({ "project": project }).to_string()).unwrap();
            path
        };

        let named = project(Some(&write("named.json", " Storefront ")));
        let empty = project(Some(&write("empty.json", "  ")));
        let long = project(Some(&write(
            "long.json",
            &"a".repeat(MAX_PROJECT_CHARS + 1),
        )));
        let limit = project(Some(&write("limit.json", &"a".repeat(MAX_PROJECT_CHARS))));
        std::fs::remove_dir_all(&dir).ok();

        assert_eq!(named.unwrap().as_deref(), Some("Storefront"));
        assert!(empty.is_err());
        assert!(long.is_err());
        assert!(limit.is_ok());
    }
}

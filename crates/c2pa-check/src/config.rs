use std::path::{Path, PathBuf};

use serde::Deserialize;
use serde_json::Value;

use crate::Expect;

pub const DEFAULT_PATH: &str = "c2pa.json";

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(rename = "$schema", default)]
    _schema: Option<String>,
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

    serde_json::from_str(&text)
        .map(Some)
        .map_err(|err| anyhow::anyhow!("{}: {err}", path.display()))
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
                "checks":[{"name":"sources","paths":["design/**/*.png"],"coverage":39,"expect":"present"}],
                "webhooks":[{"url":"https://h/hook","events":["asset.lost"]}],
                "monitors":[{"name":"CDN"}],"domains":["example.com"]}"#,
        )
        .unwrap();
        let typo =
            serde_json::from_str::<Config>(r#"{"checks":[{"name":"a","paths":[],"covrage":1}]}"#);

        assert_eq!(good.checks[0].coverage, Some(39.0));
        assert_eq!(good.checks[0].expect, Some(Expect::Present));
        assert_eq!(good.domains, ["example.com"]);
        assert!(typo.is_err());
        assert!(load(None).unwrap().is_none() || Path::new(DEFAULT_PATH).exists());
        assert!(load(Some(Path::new("/nonexistent/c2pa.json"))).is_err());
    }
}

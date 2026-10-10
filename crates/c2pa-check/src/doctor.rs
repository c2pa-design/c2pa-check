use std::time::Duration;

use base64::Engine as _;
use clap::Args;
use serde::Serialize;
use serde_json::Value;

use crate::env;

const TIMEOUT: Duration = Duration::from_secs(10);
const KEY_SECRET_LEN: usize = 32;
const WEBHOOK_PREFIX: &str = "whsec_";
pub const MIN_NODE_MAJOR: u32 = 18;
const EXIT_FAILED: u8 = 1;
const MAX_BODY_BYTES: u64 = 64 * 1024;
const KEY_PREVIEW_LEN: usize = 14;
const SKILL_URL: &str = "https://c2pa.design/skills/c2pa-integrate/SKILL.md";
const SKILL_PATH: &str = "skills/c2pa-integrate/SKILL.md";
const SKILL_ROOTS: [&str; 2] = [".claude", ".agents"];
const MAX_SKILL_BYTES: u64 = 512 * 1024;

#[derive(Args)]
pub struct DoctorArgs {
    #[arg(long, help = "print one JSON document")]
    json: bool,

    #[arg(
        long,
        value_delimiter = ',',
        value_name = "CHECKS",
        help = "checks that must be ok, e.g. --require api_key,webhook_secret: a warning or a skipped check then fails (exit 1)"
    )]
    require: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
enum State {
    Ok,
    Warn,
    Fail,
    Skip,
}

#[derive(Debug, Serialize)]
struct Check {
    name: &'static str,
    state: State,
    detail: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    data: Option<Value>,
}

fn check(name: &'static str, state: State, detail: impl Into<String>) -> Check {
    Check {
        name,
        state,
        detail: detail.into(),
        data: None,
    }
}

struct Setup {
    base: String,
    key: Option<String>,
    webhook_secret: Option<String>,
    node_version: Option<String>,
    skill_url: String,
}

impl Setup {
    fn from_env() -> Self {
        Self {
            base: env::api_base(),
            key: env::api_key(),
            webhook_secret: env::value("C2PA_WEBHOOK_SECRET"),
            node_version: env::value("C2PA_CHECK_NODE_VERSION"),
            skill_url: env::value("C2PA_SKILL_URL").unwrap_or_else(|| SKILL_URL.to_string()),
        }
    }
}

fn diagnose(setup: &Setup) -> Vec<Check> {
    let key = setup.key.as_deref();
    let mut checks = vec![key_format(key)];
    checks.extend(remote(&setup.base, key.filter(|k| key_type(k).is_some())));
    checks.push(webhook_secret(setup.webhook_secret.as_deref()));
    checks.push(node(setup.node_version.as_deref()));
    checks
}

pub fn run(args: &DoctorArgs) -> anyhow::Result<u8> {
    let setup = Setup::from_env();
    let mut checks = diagnose(&setup);
    checks.push(skill(&installed_skills(), || {
        latest_skill(&setup.skill_url)
    }));
    require(&mut checks, &args.require)?;
    let failed = checks.iter().any(|c| c.state == State::Fail);
    if args.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "ok": !failed,
                "api_base": setup.base,
                "checks": checks,
            }))?
        );
    } else {
        for c in &checks {
            let tag = match c.state {
                State::Ok => "ok  ",
                State::Warn => "warn",
                State::Fail => "FAIL",
                State::Skip => "skip",
            };
            println!("{tag}  {:<15} {}", c.name, c.detail);
        }
    }

    Ok(if failed { EXIT_FAILED } else { 0 })
}

fn key_type(key: &str) -> Option<&'static str> {
    let (kind, secret) = match key.strip_prefix("c2pa_live_") {
        Some(rest) => ("live", rest),
        None => ("test", key.strip_prefix("c2pa_test_")?),
    };
    (secret.len() == KEY_SECRET_LEN && secret.bytes().all(|b| b.is_ascii_alphanumeric()))
        .then_some(kind)
}

fn key_format(key: Option<&str>) -> Check {
    match key {
        None => check(
            "api_key",
            State::Warn,
            "C2PA_API_KEY is not set; local checks work, hosted signing and the API do not",
        ),
        Some(key) => match key_type(key) {
            Some(kind) => check(
                "api_key",
                State::Ok,
                format!("{kind} key {}…", &key[..KEY_PREVIEW_LEN]),
            ),
            None => check(
                "api_key",
                State::Fail,
                "C2PA_API_KEY is malformed: expected c2pa_live_ or c2pa_test_ followed by 32 letters and digits",
            ),
        },
    }
}

enum Answer {
    Http(u16, Value),
    Unreachable(String),
}

fn get(url: &str, key: Option<&str>) -> Answer {
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .timeout_global(Some(TIMEOUT))
        .http_status_as_error(false)
        .build()
        .into();
    let mut request = agent.get(url).header(
        "User-Agent",
        &format!("c2pa-check/{}", env!("CARGO_PKG_VERSION")),
    );
    if let Some(key) = key {
        request = request.header("Authorization", &format!("Bearer {key}"));
    }
    match request.call() {
        Ok(mut response) => {
            let status = response.status().as_u16();
            let body = response
                .body_mut()
                .with_config()
                .limit(MAX_BODY_BYTES)
                .read_to_vec()
                .ok()
                .and_then(|bytes| serde_json::from_slice(&bytes).ok())
                .unwrap_or(Value::Null);
            Answer::Http(status, body)
        }
        Err(err) => Answer::Unreachable(err.to_string()),
    }
}

fn remote(base: &str, key: Option<&str>) -> Vec<Check> {
    let base = base.trim_end_matches('/');
    match key {
        None => vec![
            reachability(base, &get(&format!("{base}/health-check"), None)),
            check("whoami", State::Skip, "no usable API key"),
        ],
        Some(key) => {
            let answer = get(&format!("{base}/whoami"), Some(key));
            let network = reachability(base, &answer);
            let whoami = match answer {
                Answer::Http(status, body) => whoami(status, body),
                Answer::Unreachable(_) => check("whoami", State::Skip, "the API is unreachable"),
            };
            vec![network, whoami]
        }
    }
}

fn reachability(base: &str, answer: &Answer) -> Check {
    match answer {
        Answer::Http(status, _) => check(
            "network",
            State::Ok,
            format!("{base} answered HTTP {status}"),
        ),
        Answer::Unreachable(reason) => check(
            "network",
            State::Fail,
            format!("{base} is unreachable: {reason}"),
        ),
    }
}

fn text(value: Option<&Value>) -> Option<&str> {
    match value? {
        Value::String(s) => Some(s.as_str()),
        Value::Object(o) => ["name", "slug", "id"]
            .iter()
            .find_map(|field| o.get(*field).and_then(Value::as_str)),
        _ => None,
    }
    .filter(|s| !s.is_empty())
}

fn whoami(status: u16, body: Value) -> Check {
    let code = body
        .pointer("/error/code")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    match status {
        200..=299 => {}
        401 | 403 => {
            return check(
                "whoami",
                State::Fail,
                format!("the API refused the key (HTTP {status} {code}); it is revoked, expired or lacks the read scope"),
            )
        }
        404 => {
            return check(
                "whoami",
                State::Warn,
                "this API does not serve /whoami yet; key type and quota are unknown",
            )
        }
        _ => {
            return check(
                "whoami",
                State::Fail,
                format!("the API answered HTTP {status} {code}"),
            )
        }
    }

    let mut parts = vec![format!(
        "{} key",
        text(body.get("key_type")).unwrap_or("unknown")
    )];
    for field in ["organization", "project", "plan"] {
        if let Some(value) = text(body.get(field)) {
            parts.push(format!("{field} {value}"));
        }
    }
    let mut exhausted = Vec::new();
    for quota in body
        .get("quota")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let metric = quota
            .get("metric")
            .and_then(Value::as_str)
            .unwrap_or("usage");
        let used = quota.get("used").and_then(Value::as_i64).unwrap_or(0);
        match quota.get("limit").and_then(Value::as_i64) {
            Some(limit) => {
                let left = limit.saturating_sub(used).max(0);
                let until = quota
                    .get("period_end")
                    .and_then(Value::as_str)
                    .map(|d| format!(" until {d}"))
                    .unwrap_or_default();
                parts.push(format!("{metric} {left} of {limit} left{until}"));
                if left == 0 {
                    exhausted.push(metric.to_string());
                }
            }
            None => parts.push(format!("{metric} {used} used, no limit")),
        }
    }

    let state = if exhausted.is_empty() {
        State::Ok
    } else {
        parts.push(format!("exhausted: {}", exhausted.join(", ")));
        State::Warn
    };
    Check {
        name: "whoami",
        state,
        detail: parts.join(", "),
        data: Some(body),
    }
}

fn webhook_secret(secret: Option<&str>) -> Check {
    let Some(secret) = secret else {
        return check(
            "webhook_secret",
            State::Skip,
            "C2PA_WEBHOOK_SECRET is not set",
        );
    };
    let standard = secret
        .strip_prefix(WEBHOOK_PREFIX)
        .and_then(|rest| base64::engine::general_purpose::STANDARD.decode(rest).ok())
        .is_some_and(|key| !key.is_empty());
    if standard {
        check("webhook_secret", State::Ok, "valid (whsec_ + base64)")
    } else {
        check(
            "webhook_secret",
            State::Fail,
            "C2PA_WEBHOOK_SECRET is invalid: expected whsec_ followed by standard base64",
        )
    }
}

fn require(checks: &mut [Check], names: &[String]) -> anyhow::Result<()> {
    for name in names {
        let Some(found) = checks.iter_mut().find(|c| c.name == name) else {
            anyhow::bail!(
                "--require {name}: no such check (api_key, network, whoami, webhook_secret, node, skill)"
            );
        };
        if found.state != State::Ok {
            found.state = State::Fail;
            found.detail = format!("required: {}", found.detail);
        }
    }

    Ok(())
}

fn skill_version(text: &str) -> Option<u32> {
    text.lines()
        .take_while(|line| !line.starts_with('#'))
        .find_map(|line| line.trim().strip_prefix("version:"))
        .and_then(|v| v.trim().trim_matches(['"', '\'']).parse().ok())
}

fn installed_skills() -> Vec<(String, u32)> {
    let home = std::env::var_os("HOME").map(std::path::PathBuf::from);
    let bases = [Some(std::path::PathBuf::from(".")), home];

    bases
        .iter()
        .flatten()
        .flat_map(|base| SKILL_ROOTS.map(|root| base.join(root).join(SKILL_PATH)))
        .filter_map(|path| {
            let version = skill_version(&std::fs::read_to_string(&path).ok()?)?;
            Some((path.display().to_string(), version))
        })
        .collect()
}

fn latest_skill(url: &str) -> Option<u32> {
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .timeout_global(Some(TIMEOUT))
        .build()
        .into();
    let bytes = agent
        .get(url)
        .call()
        .ok()?
        .body_mut()
        .with_config()
        .limit(MAX_SKILL_BYTES)
        .read_to_vec()
        .ok()?;

    skill_version(&String::from_utf8_lossy(&bytes))
}

fn skill(installed: &[(String, u32)], latest: impl FnOnce() -> Option<u32>) -> Check {
    if installed.is_empty() {
        return check("skill", State::Skip, "c2pa-integrate is not installed here");
    }
    let Some(latest) = latest() else {
        return check(
            "skill",
            State::Skip,
            "the latest skill version could not be fetched",
        );
    };
    match installed.iter().find(|(_, version)| *version < latest) {
        Some((path, version)) => check(
            "skill",
            State::Warn,
            format!("{path} is version {version}, version {latest} is out: npx skills update c2pa-integrate"),
        ),
        None => check("skill", State::Ok, format!("c2pa-integrate version {latest}")),
    }
}

fn node(version: Option<&str>) -> Check {
    let Some(version) = version else {
        return check("node", State::Skip, "not run through npx");
    };
    let major = version
        .trim_start_matches('v')
        .split('.')
        .next()
        .and_then(|m| m.parse::<u32>().ok());
    match major {
        Some(major) if major >= MIN_NODE_MAJOR => {
            check("node", State::Ok, format!("Node.js {version}"))
        }
        _ => check(
            "node",
            State::Fail,
            format!("Node.js {version} is older than {MIN_NODE_MAJOR}; upgrade Node.js"),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_server::serve;

    fn live_key() -> String {
        format!("c2pa_live_{}", "a".repeat(KEY_SECRET_LEN))
    }

    fn setup(base: String, key: Option<String>) -> Setup {
        Setup {
            base,
            key,
            webhook_secret: None,
            node_version: None,
            skill_url: String::new(),
        }
    }

    fn find<'a>(checks: &'a [Check], name: &str) -> &'a Check {
        checks
            .iter()
            .find(|c| c.name == name)
            .expect("the check ran")
    }

    fn diagnose_against(status: u16, body: &'static str) -> (Vec<Check>, Vec<String>) {
        let (base, server) = serve(1, move |request| {
            assert_eq!(request.authorization, format!("Bearer {}", live_key()));
            (status, body.to_string())
        });
        let checks = diagnose(&setup(base, Some(live_key())));
        (checks, server.join().unwrap())
    }

    #[test]
    fn whoami_200_reports_key_organization_plan_and_quota() {
        let (checks, paths) = diagnose_against(
            200,
            r#"{"key_type":"live","organization":{"slug":"acme"},"plan":"team","quota":[{"metric":"verifications","used":1,"limit":10}]}"#,
        );

        assert_eq!(paths, ["/v1/whoami"]);
        assert_eq!(find(&checks, "network").state, State::Ok);
        let whoami = find(&checks, "whoami");
        assert_eq!(whoami.state, State::Ok);
        assert_eq!(
            whoami.detail,
            "live key, organization acme, plan team, verifications 9 of 10 left"
        );
        assert!(whoami.data.is_some());
    }

    #[test]
    fn whoami_401_fails_with_the_error_code() {
        let (checks, _) = diagnose_against(401, r#"{"error":{"code":"unauthorized"}}"#);

        let whoami = find(&checks, "whoami");
        assert_eq!(whoami.state, State::Fail);
        assert!(
            whoami.detail.contains("HTTP 401 unauthorized"),
            "{}",
            whoami.detail
        );
        assert_eq!(find(&checks, "network").state, State::Ok);
    }

    #[test]
    fn whoami_404_warns_that_the_api_is_older() {
        let (checks, _) = diagnose_against(404, "not json");

        assert_eq!(find(&checks, "whoami").state, State::Warn);
        assert!(!checks.iter().any(|c| c.state == State::Fail));
    }

    #[test]
    fn whoami_with_exhausted_quota_warns() {
        let (checks, _) = diagnose_against(
            200,
            r#"{"key_type":"test","quota":[{"metric":"signatures","used":12,"limit":10}]}"#,
        );

        let whoami = find(&checks, "whoami");
        assert_eq!(whoami.state, State::Warn);
        assert!(whoami.detail.contains("signatures 0 of 10 left"));
        assert!(whoami.detail.ends_with("exhausted: signatures"));
    }

    #[test]
    fn whoami_5xx_fails() {
        let (checks, _) = diagnose_against(503, "{}");

        assert_eq!(find(&checks, "whoami").state, State::Fail);
    }

    #[test]
    fn an_oversized_whoami_body_is_dropped_not_buffered() {
        let (base, server) = serve(1, |_| {
            (
                200,
                format!(
                    r#"{{"key_type":"{}"}}"#,
                    "x".repeat(2 * MAX_BODY_BYTES as usize)
                ),
            )
        });
        let checks = diagnose(&setup(base, Some(live_key())));
        server.join().unwrap();

        let whoami = find(&checks, "whoami");
        assert_eq!(whoami.state, State::Ok);
        assert_eq!(whoami.detail, "unknown key");
    }

    #[test]
    fn without_a_usable_key_only_the_health_check_is_called() {
        let (base, server) = serve(1, |request| {
            assert!(request.authorization.is_empty());
            (200, "{}".into())
        });
        let checks = diagnose(&setup(base, Some("c2pa_live_short".into())));

        assert_eq!(server.join().unwrap(), ["/v1/health-check"]);
        assert_eq!(find(&checks, "api_key").state, State::Fail);
        assert_eq!(find(&checks, "whoami").state, State::Skip);
    }

    #[test]
    fn an_unreachable_api_fails_the_network_check() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        drop(listener);

        let checks = diagnose(&setup(format!("http://{address}/v1/"), Some(live_key())));

        assert_eq!(find(&checks, "network").state, State::Fail);
        assert_eq!(find(&checks, "whoami").state, State::Skip);
    }

    #[test]
    fn huge_quota_numbers_do_not_overflow() {
        let body =
            serde_json::json!({"quota": [{"metric": "m", "used": i64::MIN, "limit": i64::MAX}]});

        let got = whoami(200, body);

        assert_eq!(got.state, State::Ok);
        assert!(got
            .detail
            .contains(&format!("m {} of {} left", i64::MAX, i64::MAX)));
    }

    #[test]
    fn a_valid_key_is_previewed_without_its_secret() {
        let got = key_format(Some(&live_key()));

        assert_eq!(got.state, State::Ok);
        assert_eq!(got.detail, "live key c2pa_live_aaaa…");
    }

    #[test]
    fn keys_with_non_ascii_or_wrong_length_are_malformed() {
        let multibyte = format!("c2pa_live_{}", "é".repeat(16));
        assert_eq!(key_type(&multibyte), None);
        assert_eq!(key_format(Some(&multibyte)).state, State::Fail);
        assert_eq!(key_type(&format!("c2pa_test_{}", "a".repeat(33))), None);
        assert_eq!(key_type(&format!("c2pa_test_{}-", "a".repeat(31))), None);
        assert_eq!(key_type("c2pa_live_"), None);
        assert_eq!(key_type(""), None);
    }

    #[test]
    fn an_empty_webhook_key_is_invalid() {
        assert_eq!(webhook_secret(Some("whsec_")).state, State::Fail);
        assert_eq!(webhook_secret(None).state, State::Skip);
    }

    #[test]
    fn unparseable_node_versions_fail() {
        assert_eq!(node(Some("banana")).state, State::Fail);
        assert_eq!(node(Some("v22.3.1")).state, State::Ok);
    }

    #[test]
    fn key_format_accepts_live_and_test_keys_only() {
        let secret = "a".repeat(32);
        assert_eq!(key_type(&format!("c2pa_live_{secret}")), Some("live"));
        assert_eq!(key_type(&format!("c2pa_test_{secret}")), Some("test"));
        assert_eq!(key_type("c2pa_live_short"), None);
        assert_eq!(key_type(&format!("sk_live_{secret}")), None);
        assert_eq!(key_format(Some("nope")).state, State::Fail);
        assert_eq!(key_format(None).state, State::Warn);
    }

    #[test]
    fn webhook_secrets_are_whsec_base64_or_invalid() {
        assert_eq!(
            webhook_secret(Some("whsec_c2VjcmV0c2VjcmV0")).state,
            State::Ok
        );
        assert_eq!(webhook_secret(Some("plainsecret")).state, State::Fail);
        assert_eq!(webhook_secret(Some("whsec_not base64!")).state, State::Fail);
    }

    #[test]
    fn a_required_check_that_only_warns_or_was_skipped_fails() {
        let mut checks = vec![key_format(None), webhook_secret(None), node(Some("22.0.0"))];

        require(
            &mut checks,
            &["api_key".into(), "webhook_secret".into(), "node".into()],
        )
        .unwrap();
        let unknown = require(&mut checks, &["nope".into()]);

        assert_eq!(checks[0].state, State::Fail);
        assert!(checks[0].detail.starts_with("required: "));
        assert_eq!(checks[1].state, State::Fail);
        assert_eq!(checks[2].state, State::Ok);
        assert!(unknown.is_err());
    }

    #[test]
    fn an_installed_skill_older_than_the_published_one_warns() {
        let text = "---\nname: c2pa-integrate\nmetadata:\n  version: \"2\"\n---\n# c2pa-integrate\nversion: 9\n";
        let old = vec![(".claude/skills/c2pa-integrate/SKILL.md".to_string(), 2)];

        assert_eq!(skill_version(text), Some(2));
        assert_eq!(skill_version("# no frontmatter"), None);
        assert_eq!(skill(&old, || Some(3)).state, State::Warn);
        assert!(skill(&old, || Some(3)).detail.contains("npx skills update"));
        assert_eq!(skill(&old, || Some(2)).state, State::Ok);
        assert_eq!(skill(&old, || None).state, State::Skip);
        assert_eq!(skill(&[], || Some(3)).state, State::Skip);
    }

    #[test]
    fn node_below_the_minimum_fails() {
        assert_eq!(node(Some("v16.20.0")).state, State::Fail);
        assert_eq!(node(Some("18.0.0")).state, State::Ok);
        assert_eq!(node(None).state, State::Skip);
    }

    #[test]
    fn whoami_reports_remaining_quota_and_warns_when_exhausted() {
        let body = serde_json::json!({
            "key_type": "live",
            "organization": {"name": "Acme"},
            "project": "web",
            "plan": "team",
            "quota": [
                {"metric": "verifications", "used": 40, "limit": 100, "period_end": "2026-11-01"},
                {"metric": "signatures", "used": 10, "limit": 10, "period_end": "2026-11-01"}
            ]
        });
        let got = whoami(200, body);

        assert_eq!(got.state, State::Warn);
        assert!(got.detail.contains("live key"));
        assert!(got.detail.contains("organization Acme"));
        assert!(got
            .detail
            .contains("verifications 60 of 100 left until 2026-11-01"));
        assert!(got.detail.contains("exhausted: signatures"));
        assert_eq!(whoami(401, Value::Null).state, State::Fail);
        assert_eq!(whoami(404, Value::Null).state, State::Warn);
    }
}

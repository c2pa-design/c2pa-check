use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use clap::{Args, ValueEnum};
use serde_json::{json, Value};

use crate::api::{Api, ApiError};
use crate::carry_cmd::write_private;
use crate::env;

const SECRET_NAME: &str = "C2PA_API_KEY";
const MIN_INTERVAL: u64 = 1;
const EXIT_NOT_APPROVED: u8 = 1;

#[derive(Copy, Clone, PartialEq, Eq, ValueEnum)]
pub enum CiTarget {
    Github,
    Gitlab,
}

#[derive(Args)]
pub struct LoginArgs {
    #[arg(
        long,
        help = "ask for a c2pa_test_ key (sandbox quota) instead of a live one"
    )]
    test: bool,

    #[arg(
        long,
        value_enum,
        help = "also store the key as the C2PA_API_KEY secret of this repository through the gh or glab CLI"
    )]
    ci: Option<CiTarget>,
}

pub fn run(args: &LoginArgs) -> anyhow::Result<u8> {
    let api = Api::new(env::api_base(), String::new());
    let mode = if args.test { "test" } else { "live" };
    let started = api.call("POST", "/device-logins", Some(&json!({ "mode": mode })))?;
    let text = |field: &str| started[field].as_str().unwrap_or_default().to_string();
    let seconds = |field: &str| started[field].as_u64().unwrap_or_default();
    if !usable(&started) {
        anyhow::bail!("c2pa.design did not start a login (unexpected answer); try again later");
    }

    eprintln!(
        "Open {} in a browser, sign in and approve the code {}.\nWaiting for the approval ({} minutes)…",
        text("verification_url"),
        text("user_code"),
        seconds("expires_in") / 60
    );

    let waited = wait(
        &api,
        &text("device_code"),
        Duration::from_secs(seconds("expires_in")),
        Duration::from_secs(seconds("interval").max(MIN_INTERVAL)),
    )?;
    let Some((key, organization)) = waited else {
        eprintln!("c2pa-check: the code was not approved in time; run `c2pa-check login` again");

        return Ok(EXIT_NOT_APPROVED);
    };

    let path = env::credentials_path()
        .ok_or_else(|| anyhow::anyhow!("no home directory to keep the key in; set HOME"))?;
    save(&path, &key)?;
    eprintln!(
        "Signed in to {organization}. The {mode} key is saved in {} and used when C2PA_API_KEY is not set.",
        path.display()
    );

    if let Some(target) = args.ci {
        let (program, arguments) = ci_command(target);
        store_secret(program, arguments, &key)?;
        eprintln!("{SECRET_NAME} is set as a CI secret of this repository ({program}).");
    }

    Ok(0)
}

fn wait(
    api: &Api,
    device_code: &str,
    expires: Duration,
    interval: Duration,
) -> Result<Option<(String, String)>, ApiError> {
    let deadline = Instant::now() + expires;
    let body = json!({ "device_code": device_code });

    while Instant::now() < deadline {
        api.pause(interval);
        match api.call("POST", "/device-logins/token", Some(&body)) {
            Ok(state) => {
                if let Some(found) = approved(&state) {
                    return Ok(Some(found));
                }
            }
            Err(err) if err.status == 404 => return Ok(None),
            Err(err) => return Err(err),
        }
    }

    Ok(None)
}

fn usable(started: &Value) -> bool {
    let filled = |field: &str| started[field].as_str().is_some_and(|v| !v.is_empty());

    filled("device_code")
        && filled("user_code")
        && started["verification_url"]
            .as_str()
            .is_some_and(|url| url.starts_with("https://") || url.starts_with("http://"))
        && started["expires_in"].as_u64().is_some_and(|s| s > 0)
}

fn approved(state: &Value) -> Option<(String, String)> {
    let key = state["api_key"].as_str().filter(|key| !key.is_empty())?;
    (state["status"] == "approved").then(|| {
        (
            key.to_string(),
            state["organization"]
                .as_str()
                .unwrap_or_default()
                .to_string(),
        )
    })
}

fn save(path: &Path, key: &str) -> anyhow::Result<()> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)
            .map_err(|err| anyhow::anyhow!("creating {}: {err}", dir.display()))?;
    }

    write_private(path, format!("{key}\n").as_bytes())
}

fn ci_command(target: CiTarget) -> (&'static str, &'static [&'static str]) {
    match target {
        CiTarget::Github => ("gh", &["secret", "set", SECRET_NAME]),
        CiTarget::Gitlab => ("glab", &["variable", "set", SECRET_NAME, "--masked"]),
    }
}

fn store_secret(program: &str, arguments: &[&str], key: &str) -> anyhow::Result<()> {
    let mut child = Command::new(program)
        .args(arguments)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .spawn()
        .map_err(|err| {
            anyhow::anyhow!(
                "could not run {program} ({err}); the key is saved locally, add {SECRET_NAME} to the CI secrets by hand"
            )
        })?;
    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(key.as_bytes())?;
    }
    if !child.wait()?.success() {
        anyhow::bail!(
            "{program} did not store the secret; the key is saved locally, add {SECRET_NAME} to the CI secrets by hand"
        );
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_server::serve;

    #[test]
    fn login_polls_until_the_approval_and_returns_the_key() {
        let answers = std::sync::Mutex::new(vec![
            r#"{"status":"approved","api_key":"c2pa_test_abc","organization":"acme"}"#,
            r#"{"status":"pending"}"#,
        ]);
        let (base, server) = serve(2, move |request| {
            assert!(request.authorization.is_empty() || request.authorization == "Bearer ");
            (200, answers.lock().unwrap().pop().unwrap().to_string())
        });
        let api = Api::new(base, String::new()).without_waiting();

        let got = wait(&api, "d", Duration::from_secs(60), Duration::from_secs(5)).unwrap();

        assert_eq!(server.join().unwrap(), ["/v1/device-logins/token"; 2]);
        assert_eq!(got, Some(("c2pa_test_abc".to_string(), "acme".to_string())));
    }

    #[test]
    fn an_expired_or_unknown_code_ends_without_a_key() {
        let (base, server) = serve(1, |_| {
            (
                404,
                r#"{"error":{"code":"not_found","retryable":false}}"#.to_string(),
            )
        });
        let api = Api::new(base, String::new()).without_waiting();

        let gone = wait(&api, "d", Duration::from_secs(60), Duration::from_secs(5)).unwrap();
        let timed_out = wait(&api, "d", Duration::ZERO, Duration::from_secs(5)).unwrap();
        server.join().unwrap();

        assert_eq!(gone, None);
        assert_eq!(timed_out, None);
    }

    #[test]
    fn a_start_answer_without_its_fields_is_not_used() {
        let good = json!({"device_code": "d", "user_code": "BCDF-GHJK",
            "verification_url": "https://app.c2pa.design/device?code=BCDF-GHJK", "expires_in": 600});
        let without = |field: &str| {
            let mut broken = good.clone();
            broken.as_object_mut().unwrap().remove(field);
            broken
        };
        let mut script = good.clone();
        script["verification_url"] = json!("javascript:alert(1)");

        assert!(usable(&good));
        for field in ["device_code", "user_code", "verification_url", "expires_in"] {
            assert!(!usable(&without(field)), "{field}");
        }
        assert!(!usable(&script));
        assert!(!usable(&Value::Null));
    }

    #[test]
    fn only_an_approved_state_with_a_key_counts() {
        assert_eq!(approved(&json!({"status": "pending"})), None);
        assert_eq!(approved(&json!({"status": "approved"})), None);
        assert_eq!(
            approved(&json!({"status": "pending", "api_key": "k"})),
            None
        );
        assert!(approved(&json!({"status": "approved", "api_key": "k"})).is_some());
    }

    #[test]
    fn the_key_is_saved_owner_only_and_handed_to_the_ci_tool_on_stdin() {
        let dir = std::env::temp_dir().join(format!("c2pa-check-login-{}", std::process::id()));
        let path = dir.join("nested").join("credentials");
        let sink = dir.join("sink");

        save(&path, "c2pa_live_x").unwrap();
        let saved = std::fs::read_to_string(&path).unwrap();
        let piped = store_secret(
            "sh",
            &["-c", &format!("cat > {}", sink.display())],
            "c2pa_live_x",
        );
        let received = std::fs::read_to_string(&sink).unwrap_or_default();
        let missing = store_secret("c2pa-check-no-such-tool", &[], "k");
        let failing = store_secret("sh", &["-c", "cat >/dev/null; exit 3"], "k");
        std::fs::remove_dir_all(&dir).ok();

        assert_eq!(saved, "c2pa_live_x\n");
        assert!(piped.is_ok());
        assert_eq!(received, "c2pa_live_x");
        assert!(missing.unwrap_err().to_string().contains("by hand"));
        assert!(failing.is_err());
        assert_eq!(ci_command(CiTarget::Github).0, "gh");
        assert_eq!(ci_command(CiTarget::Gitlab).1[0], "variable");
    }
}

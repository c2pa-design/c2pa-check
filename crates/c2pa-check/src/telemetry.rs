use std::sync::OnceLock;
use std::time::Duration;

use serde_json::json;

use crate::env;

const TIMEOUT: Duration = Duration::from_secs(3);
const MAX_CODE: usize = 64;
pub const SEND_COMMAND: &str = "report-send";

static CODE: OnceLock<String> = OnceLock::new();
static MIME: OnceLock<String> = OnceLock::new();

pub fn note(code: &str) {
    let _ = CODE.set(slug(code));
}

pub fn note_mime(mime: &str) {
    let _ = MIME.set(mime.to_ascii_lowercase());
}

fn slug(code: &str) -> String {
    code.to_ascii_lowercase()
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | ':' | '-') {
                c
            } else {
                '_'
            }
        })
        .take(MAX_CODE)
        .collect()
}

fn known<'a>(value: &'a str, list: &[&str]) -> &'a str {
    if list.contains(&value) {
        value
    } else {
        "other"
    }
}

fn enabled(lookup: impl Fn(&str) -> Option<String>, offline: bool) -> bool {
    let off = |name: &str, values: &[&str]| {
        lookup(name).is_some_and(|v| values.contains(&v.to_ascii_lowercase().as_str()))
    };

    !offline
        && !off("C2PA_TELEMETRY", &["0", "off", "false", "no"])
        && !lookup("DO_NOT_TRACK").is_some_and(|v| v != "0")
}

pub fn panic_hook() {
    let default = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        if let Some(at) = info.location() {
            let file = at.file().rsplit(['/', '\\']).next().unwrap_or_default();
            note(&format!("panic.{file}:{}", at.line()));
        }
        default(info);
    }));
}

pub fn report(command: &str, exit_code: u8, offline: bool) {
    if cfg!(test) || !enabled(env::value, offline) {
        return;
    }

    let fallback = match exit_code {
        2 => "usage_or_io",
        3 => "unreadable",
        4 => "network",
        5 => "carry_refused",
        _ => "crash",
    };
    let mut body = json!({
        "version": env!("CARGO_PKG_VERSION"),
        "os": known(std::env::consts::OS, &["linux", "macos", "windows"]),
        "arch": known(std::env::consts::ARCH, &["x86_64", "aarch64"]),
        "command": command,
        "exit_code": exit_code,
        "code": CODE.get().map_or(fallback, String::as_str),
        "ci": env::value("CI").is_some(),
    });
    if let Some(mime) = MIME.get() {
        body["mime"] = json!(mime);
    }

    let Ok(exe) = std::env::current_exe() else {
        return;
    };
    let spawned = std::process::Command::new(exe)
        .args([SEND_COMMAND, &body.to_string()])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn();
    if spawned.is_ok() {
        eprintln!(
            "c2pa-check: sending an anonymous error report ({body}); no file names, paths, hashes or keys. C2PA_TELEMETRY=0 turns it off."
        );
    }
}

pub fn send(body: &str) {
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .timeout_global(Some(TIMEOUT))
        .http_status_as_error(false)
        .build()
        .into();
    let _ = agent
        .post(&format!(
            "{}/cli-reports",
            env::api_base().trim_end_matches('/')
        ))
        .header("Content-Type", "application/json")
        .send(body);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn with(set: &'static [(&'static str, &'static str)]) -> impl Fn(&str) -> Option<String> {
        move |name| {
            set.iter()
                .find(|(key, _)| *key == name)
                .map(|(_, v)| v.to_string())
        }
    }

    #[test]
    fn reports_are_on_unless_the_user_or_the_flag_says_no() {
        assert!(enabled(with(&[]), false));
        assert!(enabled(with(&[("DO_NOT_TRACK", "0")]), false));
        assert!(!enabled(with(&[]), true));
        assert!(!enabled(with(&[("C2PA_TELEMETRY", "0")]), false));
        assert!(!enabled(with(&[("C2PA_TELEMETRY", "OFF")]), false));
        assert!(!enabled(with(&[("DO_NOT_TRACK", "1")]), false));
    }

    #[test]
    fn a_code_cannot_carry_a_path_or_free_text() {
        assert_eq!(
            slug("api.402.usage_limit_exceeded"),
            "api.402.usage_limit_exceeded"
        );
        assert_eq!(
            slug("/Users/me/secret file.png"),
            "_users_me_secret_file.png"
        );
        assert_eq!(slug(&"x".repeat(200)).len(), MAX_CODE);
    }
}

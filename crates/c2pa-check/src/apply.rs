use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use base64::Engine as _;
use clap::Args;
use serde_json::{json, Value};

use crate::api::{scoped, Api};
use crate::carry_cmd::write_private;
use crate::config::Config;
use crate::env;

const SECRET_BYTES: usize = 32;
const SECRET_PREFIX: &str = "whsec_";
const VERIFY_EVERY: Duration = Duration::from_secs(15);
const EXIT_PENDING: u8 = 1;

#[derive(Args)]
pub struct ApplyArgs {
    #[arg(
        long,
        value_name = "PATH",
        help = "keep the webhook secret in this file (created owner-only when missing, reused when present) instead of C2PA_WEBHOOK_SECRET"
    )]
    secret_out: Option<PathBuf>,

    #[arg(
        long,
        value_name = "SECONDS",
        default_value_t = 0,
        help = "keep checking domain ownership for this long; exit 1 if a domain is still pending"
    )]
    wait: u64,

    #[arg(long, help = "send a signed ping to every webhook endpoint afterwards")]
    ping: bool,
}

pub fn run(args: &ApplyArgs, config: &Config) -> anyhow::Result<u8> {
    let api = Api::from_env()?;

    webhooks(&api, args, config)?;
    monitors(&api, config)?;
    let pending = domains(&api, config, Duration::from_secs(args.wait))?;

    Ok(if pending && args.wait > 0 {
        EXIT_PENDING
    } else {
        0
    })
}

fn items(answer: &Value) -> impl Iterator<Item = &Value> {
    answer["items"].as_array().into_iter().flatten()
}

fn text<'a>(value: &'a Value, field: &str) -> &'a str {
    value[field].as_str().unwrap_or_default()
}

fn secret(path: Option<&Path>) -> anyhow::Result<Option<String>> {
    if let Some(secret) = env::value("C2PA_WEBHOOK_SECRET") {
        return Ok(Some(secret));
    }
    let Some(path) = path else {
        return Ok(None);
    };
    match std::fs::read_to_string(path) {
        Ok(existing) if !existing.trim().is_empty() => {
            return Ok(Some(existing.trim().to_string()))
        }
        Ok(_) => {}
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
        Err(err) => anyhow::bail!("reading {}: {err}", path.display()),
    }

    let mut random = [0u8; SECRET_BYTES];
    getrandom::fill(&mut random).map_err(|e| anyhow::anyhow!("no random source: {e}"))?;
    let secret = format!(
        "{SECRET_PREFIX}{}",
        base64::engine::general_purpose::STANDARD.encode(random)
    );
    write_private(path, format!("{secret}\n").as_bytes())?;

    Ok(Some(secret))
}

fn webhooks(api: &Api, args: &ApplyArgs, config: &Config) -> anyhow::Result<()> {
    if config.webhooks.is_empty() {
        return Ok(());
    }

    let secret = secret(args.secret_out.as_deref())?;
    if secret.is_none() {
        let existing = api.get("/webhooks")?;
        let missing = config
            .webhooks
            .iter()
            .find(|w| !items(&existing).any(|e| text(e, "url") == w.url));
        if let Some(webhook) = missing {
            anyhow::bail!(
                "{} is not registered yet and its secret needs somewhere to go: set C2PA_WEBHOOK_SECRET \
(whsec_ + `openssl rand -base64 32`) or pass --secret-out PATH",
                webhook.url
            );
        }
    }

    for webhook in &config.webhooks {
        let mut body = json!({ "url": webhook.url, "events": webhook.events });
        if let Some(secret) = &secret {
            body["secret"] = json!(secret);
        }
        let endpoint = api.call("PUT", "/webhooks", Some(&body))?;
        let outcome = if endpoint.get("secret").is_some() {
            "created"
        } else {
            "up to date"
        };
        println!("webhook  {}  {outcome}", webhook.url);
        if args.ping {
            api.call(
                "POST",
                &format!("/webhooks/{}/test", text(&endpoint, "id")),
                None,
            )?;
            println!("webhook  {}  ping queued", webhook.url);
        }
    }

    Ok(())
}

fn monitors(api: &Api, config: &Config) -> anyhow::Result<()> {
    if config.monitors.is_empty() {
        return Ok(());
    }

    let existing = api.get("/monitors")?;
    for monitor in &config.monitors {
        let name = text(monitor, "name");
        if name.is_empty() {
            anyhow::bail!("every monitor needs a name");
        }
        let body = scoped(monitor.clone());
        match items(&existing).find(|m| text(m, "name") == name) {
            Some(found) => {
                api.call(
                    "PATCH",
                    &format!("/monitors/{}", text(found, "id")),
                    Some(&body),
                )?;
                println!("monitor  {name}  up to date");
            }
            None => {
                api.call("POST", "/monitors", Some(&body))?;
                println!("monitor  {name}  created");
            }
        }
    }

    Ok(())
}

fn domains(api: &Api, config: &Config, wait: Duration) -> anyhow::Result<bool> {
    if config.domains.is_empty() {
        return Ok(false);
    }

    let existing = api.get("/domains")?;
    let mut pending = Vec::new();
    for host in &config.domains {
        let found = items(&existing).find(|d| text(d, "host").eq_ignore_ascii_case(host));
        let domain = match found {
            Some(domain) => domain.clone(),
            None => api.call("POST", "/domains", Some(&scoped(json!({ "host": host }))))?,
        };
        if text(&domain, "state") == "pending" {
            pending.push(domain);
        } else {
            println!("domain   {host}  {}", text(&domain, "state"));
        }
    }

    let deadline = Instant::now() + wait;
    loop {
        pending.retain(|domain| {
            let verified = api
                .call(
                    "POST",
                    &format!("/domains/{}/verify", text(domain, "id")),
                    None,
                )
                .is_ok();
            if verified {
                println!("domain   {}  verified", text(domain, "host"));
            }
            !verified
        });
        if pending.is_empty() || Instant::now() + VERIFY_EVERY > deadline {
            break;
        }
        std::thread::sleep(VERIFY_EVERY);
    }

    for domain in &pending {
        println!(
            "domain   {}  pending: add the DNS TXT record `{}`, or serve `{}` at {}",
            text(domain, "host"),
            text(domain, "txt_record"),
            text(domain, "file_token"),
            text(domain, "file_url"),
        );
    }

    Ok(!pending.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_server::serve;

    fn config() -> Config {
        serde_json::from_str(
            r#"{"webhooks":[{"url":"https://h/hook","events":["asset.lost"]}],
                "monitors":[{"name":"CDN","checkpoints":[]},{"name":"New","checkpoints":[]}],
                "domains":["Example.com","new.example"]}"#,
        )
        .unwrap()
    }

    #[test]
    fn apply_creates_what_is_missing_and_updates_what_exists() {
        if env::value("C2PA_WEBHOOK_SECRET").is_some() {
            return;
        }
        let dir = std::env::temp_dir().join(format!("c2pa-check-apply-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let secret_path = dir.join("secret");
        let (tx, rx) = std::sync::mpsc::channel();
        let (base, server) = serve(8, move |request| {
            tx.send(String::from_utf8_lossy(&request.body).to_string())
                .unwrap();
            let body = match request.path.as_str() {
                "/v1/webhooks" => r#"{"id":"w1","secret":"whsec_x"}"#,
                "/v1/monitors" if request.body.is_empty() => {
                    r#"{"items":[{"id":"m1","name":"CDN"}]}"#
                }
                "/v1/domains" if request.body.is_empty() => {
                    r#"{"items":[{"id":"d1","host":"example.com","state":"verified"}]}"#
                }
                "/v1/domains" => {
                    r#"{"id":"d2","host":"new.example","state":"pending","txt_record":"c2pa=1"}"#
                }
                "/v1/domains/d2/verify" => {
                    return (
                        403,
                        r#"{"error":{"code":"forbidden","retryable":false}}"#.into(),
                    )
                }
                _ => "{}",
            };
            (200, body.to_string())
        });
        let api = Api::new(base, "k".into()).without_waiting();
        let args = ApplyArgs {
            secret_out: Some(secret_path.clone()),
            wait: 0,
            ping: true,
        };

        webhooks(&api, &args, &config()).unwrap();
        monitors(&api, &config()).unwrap();
        let pending = domains(&api, &config(), Duration::ZERO).unwrap();
        let written = std::fs::read_to_string(&secret_path).unwrap();
        let reused = secret(Some(&secret_path)).unwrap().unwrap();
        std::fs::remove_dir_all(&dir).ok();

        assert_eq!(
            server.join().unwrap(),
            [
                "/v1/webhooks",
                "/v1/webhooks/w1/test",
                "/v1/monitors",
                "/v1/monitors/m1",
                "/v1/monitors",
                "/v1/domains",
                "/v1/domains",
                "/v1/domains/d2/verify"
            ]
        );
        assert!(pending);
        assert!(written.starts_with(SECRET_PREFIX));
        assert_eq!(reused, written.trim());
        let put: Value = serde_json::from_str(&rx.recv().unwrap()).unwrap();
        assert_eq!(put["secret"], reused);
        assert_eq!(put["events"], json!(["asset.lost"]));
    }

    #[test]
    fn a_new_webhook_without_a_place_for_its_secret_changes_nothing() {
        if env::value("C2PA_WEBHOOK_SECRET").is_some() {
            return;
        }
        let (base, server) = serve(1, |_| (200, r#"{"items":[]}"#.to_string()));
        let api = Api::new(base, "k".into()).without_waiting();
        let args = ApplyArgs {
            secret_out: None,
            wait: 0,
            ping: false,
        };

        let err = webhooks(&api, &args, &config()).unwrap_err();

        assert_eq!(server.join().unwrap(), ["/v1/webhooks"]);
        assert!(err.to_string().contains("--secret-out"));
    }
}

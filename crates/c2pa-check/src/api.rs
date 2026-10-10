use std::time::Duration;

use serde_json::Value;

use crate::env;

const TIMEOUT: Duration = Duration::from_secs(30);
const MAX_ATTEMPTS: u32 = 5;
const BACKOFF_BASE_MS: u64 = 500;
const BACKOFF_CAP_MS: u64 = 30_000;

#[derive(Debug)]
pub struct ApiError {
    pub status: u16,
    pub code: String,
    detail: String,
}

impl std::fmt::Display for ApiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.status {
            0 => write!(f, "c2pa.design is unreachable: {}", self.detail),
            status => write!(
                f,
                "c2pa.design answered HTTP {status} {}: {}",
                self.code, self.detail
            ),
        }
    }
}

impl std::error::Error for ApiError {}

pub fn scoped(mut body: Value) -> Value {
    if body.get("project_id").is_none() {
        if let Some(project) = env::value("C2PA_PROJECT_ID") {
            body["project_id"] = Value::String(project);
        }
    }
    body
}

pub struct Api {
    base: String,
    key: String,
    agent: ureq::Agent,
    sleep: fn(Duration),
}

impl Api {
    pub fn from_env() -> anyhow::Result<Self> {
        let key = env::api_key().ok_or_else(|| {
            anyhow::anyhow!(
                "C2PA_API_KEY is not set (create one at https://app.c2pa.design, API keys)"
            )
        })?;

        Ok(Self::new(env::api_base(), key))
    }

    pub fn new(base: String, key: String) -> Self {
        Self {
            base: base.trim_end_matches('/').to_string(),
            key,
            agent: ureq::Agent::config_builder()
                .timeout_global(Some(TIMEOUT))
                .http_status_as_error(false)
                .build()
                .into(),
            sleep: std::thread::sleep,
        }
    }

    #[cfg(test)]
    pub fn without_waiting(mut self) -> Self {
        self.sleep = |_| {};
        self
    }

    pub fn pause(&self, duration: Duration) {
        (self.sleep)(duration);
    }

    pub fn get(&self, path: &str) -> Result<Value, ApiError> {
        self.call("GET", path, None)
    }

    pub fn call(&self, method: &str, path: &str, body: Option<&Value>) -> Result<Value, ApiError> {
        let url = format!("{}{path}", self.base);
        let payload = body.map(|b| b.to_string());
        let mut attempt = 1;

        loop {
            let (failure, wait) = match self.send(method, &url, payload.as_deref()) {
                Ok((status, _, value)) if (200..300).contains(&status) => return Ok(value),
                Ok((status, retry_after, value)) => {
                    let (failure, retryable) = refusal(status, &value);
                    if !retryable {
                        return Err(failure);
                    }
                    (failure, retry_after)
                }
                Err(reason) => (
                    ApiError {
                        status: 0,
                        code: String::new(),
                        detail: reason,
                    },
                    None,
                ),
            };
            if attempt >= MAX_ATTEMPTS {
                return Err(failure);
            }
            eprintln!(
                "c2pa-check: {method} {path}: {failure}; retrying ({attempt}/{MAX_ATTEMPTS})"
            );
            (self.sleep)(pause(wait, attempt));
            attempt += 1;
        }
    }

    fn send(
        &self,
        method: &str,
        url: &str,
        payload: Option<&str>,
    ) -> Result<(u16, Option<Duration>, Value), String> {
        let authorization = if self.key.is_empty() {
            String::new()
        } else {
            format!("Bearer {}", self.key)
        };
        let agent = concat!("c2pa-check/", env!("CARGO_PKG_VERSION"));
        let sent = match (method, payload) {
            ("GET", _) => self
                .agent
                .get(url)
                .header("Authorization", &authorization)
                .header("User-Agent", agent)
                .call(),
            (_, body) => {
                let request = match method {
                    "PUT" => self.agent.put(url),
                    "PATCH" => self.agent.patch(url),
                    _ => self.agent.post(url),
                }
                .header("Authorization", &authorization)
                .header("User-Agent", agent)
                .header("Content-Type", "application/json");
                match body {
                    Some(body) => request.send(body),
                    None => request.send_empty(),
                }
            }
        };
        let mut response = sent.map_err(|err| err.to_string())?;
        let status = response.status().as_u16();
        let retry_after = response
            .headers()
            .get("retry-after")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.trim().parse::<u64>().ok())
            .filter(|seconds| *seconds > 0)
            .map(Duration::from_secs);
        let value = response
            .body_mut()
            .read_to_vec()
            .ok()
            .and_then(|bytes| serde_json::from_slice(&bytes).ok())
            .unwrap_or(Value::Null);

        Ok((status, retry_after, value))
    }
}

fn refusal(status: u16, body: &Value) -> (ApiError, bool) {
    let error = body.get("error");
    let field = |name: &str| {
        error
            .and_then(|e| e.get(name))
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string()
    };
    let retryable = error
        .and_then(|e| e.get("retryable"))
        .and_then(Value::as_bool)
        .unwrap_or(status >= 500);

    (
        ApiError {
            status,
            code: field("code"),
            detail: field("message"),
        },
        retryable,
    )
}

fn pause(retry_after: Option<Duration>, attempt: u32) -> Duration {
    match retry_after {
        Some(asked) => asked.min(Duration::from_millis(BACKOFF_CAP_MS)),
        None => backoff(attempt),
    }
}

fn backoff(attempt: u32) -> Duration {
    let cap = BACKOFF_CAP_MS.min(BACKOFF_BASE_MS << attempt.min(16));
    let mut random = [0u8; 8];
    let _ = getrandom::fill(&mut random);

    Duration::from_millis(u64::from_le_bytes(random) % (cap + 1))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_server::serve;

    #[test]
    fn a_retryable_error_is_retried_and_a_final_one_is_not() {
        let answers = std::sync::Mutex::new(vec![
            (200, r#"{"ok":true}"#),
            (
                503,
                r#"{"error":{"code":"engine_unavailable","retryable":true}}"#,
            ),
        ]);
        let (base, server) = serve(2, move |_| {
            let (status, body) = answers.lock().unwrap().pop().unwrap();
            (status, body.to_string())
        });
        let got = Api::new(base, "k".into()).without_waiting().call(
            "POST",
            "/assets",
            Some(&serde_json::json!({})),
        );
        server.join().unwrap();

        assert_eq!(got.unwrap()["ok"], true);

        let (base, server) = serve(1, |_| {
            (
                402,
                r#"{"error":{"code":"usage_limit_exceeded","message":"spent","retryable":false}}"#
                    .to_string(),
            )
        });
        let err = Api::new(base, "k".into())
            .without_waiting()
            .get("/whoami")
            .unwrap_err();

        assert_eq!(server.join().unwrap().len(), 1);
        assert_eq!(
            (err.status, err.code.as_str()),
            (402, "usage_limit_exceeded")
        );
    }

    #[test]
    fn an_unreachable_api_gives_up_after_five_attempts() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let base = format!("http://{}/v1", listener.local_addr().unwrap());
        drop(listener);

        let err = Api::new(base, "k".into())
            .without_waiting()
            .get("/whoami")
            .unwrap_err();

        assert_eq!(err.status, 0);
        assert_eq!(
            pause(Some(Duration::from_secs(86_400)), 1),
            Duration::from_millis(BACKOFF_CAP_MS)
        );
        assert_eq!(
            pause(Some(Duration::from_secs(2)), 1),
            Duration::from_secs(2)
        );
        assert!(refusal(503, &Value::Null).1);
        assert!(!refusal(400, &Value::Null).1);
        assert!(!refusal(503, &serde_json::json!({"error": {"retryable": false}})).1);
        assert!(backoff(1) <= Duration::from_millis(1000));
        assert!(backoff(60) <= Duration::from_millis(BACKOFF_CAP_MS));
    }
}

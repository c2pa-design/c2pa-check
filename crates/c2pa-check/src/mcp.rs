use std::io::{BufRead, Write};

use c2pa_check_core::report::TrustSelector;
use c2pa_check_core::{Options, TrustBundle, Verifier};
use serde_json::{json, Value};

const PROTOCOL_VERSIONS: [&str; 4] = ["2026-07-28", "2025-11-25", "2025-06-18", "2025-03-26"];

pub struct Server {
    bundle: TrustBundle,
    verifiers: Vec<Verifier>,
}

impl Server {
    pub fn new(bundle: TrustBundle) -> anyhow::Result<Self> {
        let mut verifiers = Vec::with_capacity(TrustSelector::ALL.len());
        for selector in TrustSelector::ALL {
            verifiers.push(Verifier::new(&bundle, selector).map_err(|err| {
                anyhow::anyhow!(
                    "the trust list {} could not be loaded ({err}); run `c2pa-check trust update`",
                    bundle.version
                )
            })?);
        }

        Ok(Self { bundle, verifiers })
    }

    fn verifier(&self, selector: TrustSelector) -> &Verifier {
        &self.verifiers[selector.index()]
    }
}

pub fn serve(bundle: TrustBundle) -> anyhow::Result<u8> {
    let server = Server::new(bundle)?;
    let stdin = std::io::stdin();
    let mut stdout = std::io::stdout();

    for line in stdin.lock().lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let request: Value = match serde_json::from_str(&line) {
            Ok(value) => value,
            Err(err) => {
                write(&mut stdout, error(Value::Null, -32700, &err.to_string()))?;

                continue;
            }
        };

        let id = request.get("id").cloned().unwrap_or(Value::Null);
        let method = request.get("method").and_then(Value::as_str).unwrap_or("");

        if id.is_null() && method.starts_with("notifications/") {
            continue;
        }

        let response = match method {
            "initialize" => ok(id, initialize(&request)),
            "tools/list" => ok(id, tools()),
            "tools/call" => match call(&request, &server) {
                Ok(result) => ok(id, result),
                Err(err) => ok(id, tool_error(&err.to_string())),
            },
            "ping" => ok(id, json!({})),
            other => error(id, -32601, &format!("unknown method {other}")),
        };

        write(&mut stdout, response)?;
    }

    Ok(0)
}

fn write(out: &mut impl Write, value: Value) -> anyhow::Result<()> {
    serde_json::to_writer(&mut *out, &value)?;
    writeln!(out)?;
    out.flush()?;

    Ok(())
}

fn ok(id: Value, result: Value) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "result": result })
}

fn error(id: Value, code: i32, message: &str) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "error": { "code": code, "message": message } })
}

fn tool_error(message: &str) -> Value {
    json!({ "isError": true, "content": [{ "type": "text", "text": message }] })
}

fn negotiate(requested: Option<&str>) -> &'static str {
    PROTOCOL_VERSIONS
        .into_iter()
        .find(|v| Some(*v) == requested)
        .unwrap_or(PROTOCOL_VERSIONS[0])
}

fn initialize(request: &Value) -> Value {
    let requested = request
        .pointer("/params/protocolVersion")
        .and_then(Value::as_str);
    json!({
        "protocolVersion": negotiate(requested),
        "capabilities": { "tools": {} },
        "serverInfo": { "name": "c2pa-check", "version": env!("CARGO_PKG_VERSION") }
    })
}

fn tools() -> Value {
    json!({ "tools": [
        {
            "name": "verify_file",
            "description": "Verify Content Credentials in a local file. Returns the normalized result document (schema v1); credential.status is absent | present_invalid | valid_untrusted | valid_trusted.",
            "inputSchema": {
                "type": "object",
                "required": ["path"],
                "properties": {
                    "path": { "type": "string" },
                    "trust": { "enum": ["official", "interim", "both", "none"] }
                }
            }
        },
        {
            "name": "verify_url",
            "description": "Fetch a public URL and verify its Content Credentials. Refuses private and link-local addresses.",
            "inputSchema": {
                "type": "object",
                "required": ["url"],
                "properties": {
                    "url": { "type": "string" },
                    "trust": { "enum": ["official", "interim", "both", "none"] }
                }
            }
        },
        {
            "name": "trust_status",
            "description": "Report which trust list this server judges signers against.",
            "inputSchema": { "type": "object", "properties": {} }
        }
    ]})
}

fn call(request: &Value, server: &Server) -> anyhow::Result<Value> {
    let params = request.get("params").cloned().unwrap_or_else(|| json!({}));
    let name = params.get("name").and_then(Value::as_str).unwrap_or("");
    let args = params
        .get("arguments")
        .cloned()
        .unwrap_or_else(|| json!({}));

    let trust = args
        .get("trust")
        .and_then(Value::as_str)
        .and_then(TrustSelector::parse)
        .unwrap_or(TrustSelector::Official);
    let options = Options::default();

    let (bytes, mime) = match name {
        "trust_status" => {
            return Ok(content(json!({
                "version": server.bundle.version,
                "sha256": server.bundle.sha256,
                "official_count": server.bundle.official_count(),
                "tsa_count": server.bundle.tsa_count()
            })))
        }
        "verify_file" => {
            let path = args
                .get("path")
                .and_then(Value::as_str)
                .ok_or_else(|| anyhow::anyhow!("path is required"))?;
            let bytes = std::fs::read(path)?;
            let mime = c2pa_check_core::media::mime_from_extension(path).to_string();
            (bytes, mime)
        }
        "verify_url" => {
            let url = args
                .get("url")
                .and_then(Value::as_str)
                .ok_or_else(|| anyhow::anyhow!("url is required"))?;
            crate::fetch::get(url)?
        }
        other => anyhow::bail!("unknown tool {other}"),
    };

    let report = server.verifier(trust).verify(&bytes, &mime, &options)?;

    Ok(content(serde_json::to_value(report)?))
}

fn content(value: Value) -> Value {
    json!({
        "content": [{ "type": "text", "text": serde_json::to_string_pretty(&value).unwrap_or_default() }],
        "structuredContent": value
    })
}

#[cfg(test)]
mod protocol_tests {
    use super::*;

    fn answered(request: Value) -> Value {
        initialize(&request)["protocolVersion"].clone()
    }

    #[test]
    fn a_supported_version_is_echoed() {
        for version in PROTOCOL_VERSIONS {
            let request = json!({"method": "initialize", "params": {"protocolVersion": version}});
            assert_eq!(answered(request), version);
        }
    }

    #[test]
    fn an_unknown_or_missing_version_gets_the_latest() {
        assert_eq!(
            answered(json!({"params": {"protocolVersion": "2024-11-05"}})),
            "2026-07-28"
        );
        assert_eq!(
            answered(json!({"params": {"protocolVersion": 7}})),
            "2026-07-28"
        );
        assert_eq!(answered(json!({"method": "initialize"})), "2026-07-28");
    }
}

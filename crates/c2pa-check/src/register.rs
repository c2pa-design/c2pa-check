use std::collections::{BTreeMap, HashSet};

use c2pa_check_core::Report;
use serde_json::{json, Value};

use crate::api::{Api, ApiError};

const SYNC_CHUNK: usize = 5000;
const REGISTER_CHUNK: usize = 500;
const SOURCE: &str = "skill";

pub struct Registered {
    pub total: usize,
    pub new: usize,
}

pub fn run(
    api: &Api,
    results: &[(String, Option<Report>)],
    unexpected: &HashSet<usize>,
) -> Result<Registered, ApiError> {
    let mut by_sha: BTreeMap<String, (&str, &Report, bool)> = BTreeMap::new();
    for (index, (target, report)) in results.iter().enumerate() {
        if let Some(report) = report {
            by_sha.entry(report.asset.sha256.to_lowercase()).or_insert((
                target.as_str(),
                report,
                !unexpected.contains(&index),
            ));
        }
    }
    let hashes: Vec<&String> = by_sha.keys().collect();
    let mut unknown = HashSet::new();
    for chunk in hashes.chunks(SYNC_CHUNK) {
        let answer = api.call(
            "POST",
            "/assets/sync",
            Some(&api.scoped(json!({ "hashes": chunk }))?),
        )?;
        for sha in answer["unknown"].as_array().into_iter().flatten() {
            unknown.extend(sha.as_str().map(str::to_lowercase));
        }
    }

    let new: Vec<&(&str, &Report, bool)> = by_sha
        .iter()
        .filter(|(sha, _)| unknown.contains(*sha))
        .map(|(_, entry)| entry)
        .collect();
    for chunk in new.chunks(REGISTER_CHUNK) {
        let items = chunk
            .iter()
            .map(|(target, report, expected)| {
                let mut item = json!({ "location": target, "source": SOURCE, "result": report });
                if !expected {
                    item["expects_credential"] = Value::Bool(false);
                }

                api.scoped(item)
            })
            .collect::<Result<Vec<Value>, ApiError>>()?;
        api.call("POST", "/assets", Some(&json!({ "items": items })))?;
    }

    Ok(Registered {
        total: by_sha.len(),
        new: new.len(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_server::serve;
    use c2pa_check_core::CredentialStatus;

    #[test]
    fn only_unknown_hashes_are_registered_once_each_with_the_whole_result() {
        let mut results = crate::tests::results_named(&[
            ("public/known.webp", CredentialStatus::Absent),
            ("public/new.webp", CredentialStatus::ValidTrusted),
            ("public/copy-of-new.webp", CredentialStatus::ValidTrusted),
        ]);
        for (i, sha) in ["aa", "BB", "bb"].iter().enumerate() {
            results[i].1.as_mut().unwrap().asset.sha256 = sha.to_string();
        }
        results.push(("broken.webp".into(), None));
        let (tx, rx) = std::sync::mpsc::channel();
        let (base, server) = serve(2, move |request| {
            let body: Value = serde_json::from_slice(&request.body).unwrap();
            tx.send(body).unwrap();
            (200, r#"{"unknown":["bb"],"items":[]}"#.to_string())
        });

        let api = Api::new(base, "k".into())
            .without_waiting()
            .with_project_id(None);

        let got = run(&api, &results, &HashSet::new()).unwrap();

        assert_eq!(server.join().unwrap(), ["/v1/assets/sync", "/v1/assets"]);
        assert_eq!((got.total, got.new), (2, 1));
        let sync = rx.recv().unwrap();
        assert_eq!(sync["hashes"], json!(["aa", "bb"]));
        assert!(sync.get("project_id").is_none());
        let item = &rx.recv().unwrap()["items"][0];
        assert_eq!(item["location"], "public/new.webp");
        assert_eq!(item["source"], "skill");
        assert_eq!(item["result"]["credential"]["status"], "valid_trusted");
        assert!(item.get("expects_credential").is_none());
        assert!(item.get("project_id").is_none());
    }

    #[test]
    fn the_named_project_is_resolved_once_and_sent_on_every_call() {
        let mut results = crate::tests::results_named(&[
            ("icons/a.svg", CredentialStatus::Absent),
            ("public/b.webp", CredentialStatus::ValidTrusted),
        ]);
        for (i, sha) in ["aa", "bb"].iter().enumerate() {
            results[i].1.as_mut().unwrap().asset.sha256 = sha.to_string();
        }
        let (tx, rx) = std::sync::mpsc::channel();
        let (base, server) = serve(3, move |request| {
            tx.send(serde_json::from_slice::<Value>(&request.body).unwrap())
                .unwrap();
            if request.path.ends_with("/projects") {
                return (200, r#"{"id":"p-1","name":"Storefront"}"#.to_string());
            }
            (200, r#"{"unknown":["aa","bb"],"items":[]}"#.to_string())
        });
        let api = Api::new(base, "k".into())
            .without_waiting()
            .with_project_id(None)
            .with_project(Some("Storefront".into()));

        run(&api, &results, &HashSet::from([0])).unwrap();

        assert_eq!(
            server.join().unwrap(),
            ["/v1/projects", "/v1/assets/sync", "/v1/assets"]
        );
        assert_eq!(rx.recv().unwrap(), json!({"name": "Storefront"}));
        assert_eq!(rx.recv().unwrap()["project_id"], "p-1");
        let items = rx.recv().unwrap()["items"].clone();
        assert_eq!(items[0]["project_id"], "p-1");
        assert_eq!(items[0]["expects_credential"], false);
        assert_eq!(items[1]["project_id"], "p-1");
        assert!(items[1].get("expects_credential").is_none());
    }

    #[test]
    fn nothing_unknown_means_no_register_call() {
        let results = crate::tests::results_named(&[("a.png", CredentialStatus::Absent)]);
        let (base, server) = serve(1, |_| (200, r#"{"unknown":[]}"#.to_string()));

        let api = Api::new(base, "k".into())
            .without_waiting()
            .with_project_id(None);

        let got = run(&api, &results, &HashSet::new()).unwrap();

        assert_eq!(server.join().unwrap(), ["/v1/assets/sync"]);
        assert_eq!(got.new, 0);
    }
}

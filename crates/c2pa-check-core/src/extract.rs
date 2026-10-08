use std::collections::HashSet;

use serde_json::Value;

use crate::classify;
use crate::explain;
use crate::report::{
    Action, Asset, Claim, Credential, CredentialStatus, EngineInfo, Ingredient, Report, Signer,
    Source, SourceCategory, TrustSelector, Validation, ValidationEntry, SCHEMA_VERSION,
};
use crate::Options;

const MAX_ACTIONS: usize = 64;
const MAX_ENTRIES: usize = 64;
const MAX_DISTINCT_CODES: usize = 256;

pub fn build(
    store: Value,
    engine: EngineInfo,
    asset: Asset,
    options: &Options,
    selector: TrustSelector,
) -> Report {
    let active = active_manifest(&store);
    let state = text(store.get("validation_state")).unwrap_or_default();

    let valid = state != "Invalid";
    let trusted = state == "Trusted";

    let credential = Credential {
        present: true,
        valid,
        trusted,
        status: classify::status(true, valid, trusted),
    };
    let signer = signer(active, trusted, selector);
    let claim = claim(active);
    let (source, actions) = source_and_actions(active);
    let ingredients = ingredients(active, options.max_ingredients);
    let validation = validation_entries(&store);

    Report {
        schema_version: SCHEMA_VERSION.to_string(),
        engine,
        credential,
        signer,
        claim,
        source,
        actions,
        ingredients,
        validation,
        asset,
        metadata: None,
        raw_manifest_store: options.include_raw.then_some(store),
    }
}

fn active_manifest(store: &Value) -> Option<&Value> {
    let manifests = store.get("manifests")?.as_object()?;

    if let Some(label) = store.get("active_manifest").and_then(Value::as_str) {
        if let Some(found) = manifests.get(label) {
            return Some(found);
        }
    }

    manifests.values().next()
}

fn text(value: Option<&Value>) -> Option<String> {
    match value? {
        Value::String(s) if !s.is_empty() => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        _ => None,
    }
}

fn signer(active: Option<&Value>, trusted: bool, selector: TrustSelector) -> Option<Signer> {
    let info = active?.get("signature_info")?;

    let issuer = text(info.get("issuer"));
    let on_trust_list = match (trusted, selector) {
        (false, _) | (_, TrustSelector::None) => "none",
        (_, TrustSelector::Interim) => "interim",
        _ => "official",
    };

    Some(Signer {
        organization: issuer.as_deref().map(organization_of),
        common_name: text(info.get("common_name")).or_else(|| issuer.clone()),
        issuer,
        cert_serial: text(info.get("cert_serial_number")),
        on_trust_list: Some(on_trust_list.to_string()),
        conformant_product: None,
        valid_from: text(info.get("valid_from")),
        valid_to: text(info.get("valid_to")),
    })
}

fn organization_of(subject: &str) -> String {
    subject
        .split(',')
        .map(str::trim)
        .find_map(|part| part.strip_prefix("O="))
        .unwrap_or(subject)
        .to_string()
}

fn claim(active: Option<&Value>) -> Option<Claim> {
    let manifest = active?;
    let generator = manifest
        .get("claim_generator_info")
        .and_then(Value::as_array)
        .and_then(|list| list.first())
        .and_then(|first| text(first.get("name")))
        .or_else(|| text(manifest.get("claim_generator")));

    let signature = manifest.get("signature_info");

    Some(Claim {
        generator,
        spec_version: text(manifest.get("claim_version"))
            .or_else(|| text(manifest.get("spec_version"))),
        signed_at: signature.and_then(|info| text(info.get("time"))),
        timestamp_authority: signature.and_then(|info| text(info.get("time_authority"))),
        algorithm: signature
            .and_then(|info| text(info.get("alg")))
            .map(|alg| alg.to_lowercase()),
    })
}

fn source_and_actions(active: Option<&Value>) -> (Source, Vec<Action>) {
    let mut category = SourceCategory::Unknown;
    let mut declared: Option<String> = None;
    let mut actions = Vec::new();

    let Some(manifest) = active else {
        return (
            Source {
                digital_source_type: None,
                category,
            },
            actions,
        );
    };

    for assertion in manifest
        .get("assertions")
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or_default()
    {
        let label = assertion.get("label").and_then(Value::as_str).unwrap_or("");
        let data = assertion.get("data");

        if label.starts_with("c2pa.actions") {
            for entry in data
                .and_then(|d| d.get("actions"))
                .and_then(Value::as_array)
                .map(Vec::as_slice)
                .unwrap_or_default()
            {
                if let Some(uri) = entry.get("digitalSourceType").and_then(Value::as_str) {
                    if let Some(found) = classify::category_of(uri) {
                        category = classify::strongest(category, found);
                        declared = Some(uri.to_string());
                    }
                }
                if let Some(name) = entry.get("action").and_then(Value::as_str) {
                    if actions.len() < MAX_ACTIONS {
                        actions.push(Action {
                            action: name.to_string(),
                            when: text(entry.get("when")),
                            software: text(entry.get("softwareAgent")).or_else(|| {
                                entry
                                    .get("softwareAgent")
                                    .and_then(|agent| text(agent.get("name")))
                            }),
                        });
                    }
                }
            }
        }

        if label.starts_with("stds.iptc") {
            let uri = data
                .and_then(|d| {
                    d.get("digitalSourceType")
                        .or_else(|| d.get("Iptc4xmpExt:DigitalSourceType"))
                })
                .and_then(Value::as_str);
            if let Some(found) = uri.and_then(classify::category_of) {
                category = classify::strongest(category, found);
                declared = uri.map(str::to_string);
            }
        }
    }

    if category == SourceCategory::Unknown {
        let generator = manifest
            .get("claim_generator_info")
            .and_then(Value::as_array)
            .and_then(|list| list.first())
            .and_then(|first| first.get("name"))
            .and_then(Value::as_str)
            .or_else(|| manifest.get("claim_generator").and_then(Value::as_str))
            .unwrap_or("");
        if let Some(found) = classify::from_generator(generator) {
            category = found;
        }
    }

    (
        Source {
            digital_source_type: declared,
            category,
        },
        actions,
    )
}

fn ingredients(active: Option<&Value>, limit: usize) -> Vec<Ingredient> {
    let Some(manifest) = active else {
        return Vec::new();
    };

    manifest
        .get("ingredients")
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or_default()
        .iter()
        .take(limit)
        .map(|item| Ingredient {
            title: text(item.get("title")),
            relationship: text(item.get("relationship")),
            credential_status: ingredient_status(item),
        })
        .collect()
}

fn ingredient_status(item: &Value) -> Option<CredentialStatus> {
    let has_manifest = item.get("active_manifest").is_some()
        || item.get("c2pa_manifest").is_some()
        || item.get("manifest_data").is_some();
    if !has_manifest {
        return Some(CredentialStatus::Absent);
    }

    let failed = item
        .get("validation_status")
        .and_then(Value::as_array)
        .map(|list| !list.is_empty())
        .unwrap_or(false);
    if failed {
        return Some(CredentialStatus::PresentInvalid);
    }

    Some(CredentialStatus::ValidUntrusted)
}

fn push(bucket: &mut Vec<ValidationEntry>, code: &str, url: Option<String>) {
    if bucket.len() >= MAX_ENTRIES {
        return;
    }
    bucket.push(ValidationEntry {
        code: code.to_string(),
        explanation_key: Some(explain::explanation_key(code)),
        url: url.or_else(|| Some(explain::documentation_url(code))),
    });
}

fn consider<'a>(value: &'a Value, out: &mut Validation, seen: &mut HashSet<&'a str>) {
    let Some(code) = value.get("code").and_then(Value::as_str) else {
        return;
    };
    if seen.len() >= MAX_DISTINCT_CODES || !seen.insert(code) {
        return;
    }
    if explain::is_informational(code) {
        return;
    }

    let url = value.get("url").and_then(Value::as_str).map(str::to_string);
    if explain::is_warning(code) {
        push(&mut out.warnings, code, url);
    } else {
        push(&mut out.errors, code, url);
    }
}

fn validation_entries(store: &Value) -> Validation {
    let mut out = Validation::default();
    let mut seen = HashSet::new();

    if let Some(results) = store.get("validation_results").and_then(Value::as_object) {
        for scope in results.values() {
            let Some(buckets) = scope.as_object() else {
                continue;
            };
            for (name, list) in buckets {
                if name == "success" {
                    continue;
                }
                for entry in list.as_array().map(Vec::as_slice).unwrap_or_default() {
                    consider(entry, &mut out, &mut seen);
                }
            }
        }
    }

    for entry in store
        .get("validation_status")
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or_default()
    {
        consider(entry, &mut out, &mut seen);
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::report::TrustSelector;

    fn engine() -> EngineInfo {
        EngineInfo {
            name: "test".into(),
            version: "0".into(),
            trust_list_version: "2026-09-09-abc".into(),
        }
    }

    fn asset() -> Asset {
        Asset {
            sha256: "ab".into(),
            mime_type: "image/jpeg".into(),
            size_bytes: 3,
            width: None,
            height: None,
            pdq: None,
            pdq_quality: None,
            ..Asset::default()
        }
    }

    fn store(state: &str) -> Value {
        serde_json::json!({
            "active_manifest": "urn:one",
            "validation_state": state,
            "manifests": {
                "urn:one": {
                    "claim_generator": "OpenAI DALL-E",
                    "claim_generator_info": [{"name": "OpenAI", "version": "1"}],
                    "signature_info": {
                        "issuer": "CN=OpenAI Media, O=OpenAI Inc.",
                        "cert_serial_number": "42",
                        "time": "2026-09-01T00:00:00Z",
                        "alg": "Ps256"
                    },
                    "assertions": [{
                        "label": "c2pa.actions.v2",
                        "data": {"actions": [{
                            "action": "c2pa.created",
                            "digitalSourceType": "http://cv.iptc.org/newscodes/digitalsourcetype/trainedAlgorithmicMedia"
                        }]}
                    }],
                    "ingredients": [{"title": "base.jpg", "relationship": "parentOf"}]
                }
            },
            "validation_results": {"activeManifest": {
                "success": [{"code": "claimSignature.validated"}],
                "failure": [{"code": "signingCredential.untrusted"}]
            }}
        })
    }

    fn report(state: &str) -> Report {
        build(
            store(state),
            engine(),
            asset(),
            &Options::default(),
            TrustSelector::Official,
        )
    }

    #[test]
    fn a_trusted_store_reads_as_valid_trusted() {
        let report = report("Trusted");

        assert_eq!(report.credential.status, CredentialStatus::ValidTrusted);
        assert!(report.credential.present);
        assert!(report.credential.valid);
        assert!(report.credential.trusted);
    }

    #[test]
    fn an_invalid_store_is_reported_not_refused() {
        let report = report("Invalid");

        assert_eq!(report.credential.status, CredentialStatus::PresentInvalid);
        assert!(report.credential.present);
        assert!(!report.credential.valid);
    }

    #[test]
    fn a_declared_source_type_wins_over_the_generator_name() {
        let report = report("Trusted");

        assert_eq!(report.source.category, SourceCategory::AiGenerated);
        assert_eq!(
            report.source.digital_source_type.as_deref(),
            Some("http://cv.iptc.org/newscodes/digitalsourcetype/trainedAlgorithmicMedia")
        );
    }

    #[test]
    fn actions_carry_their_name_and_the_ingredient_list_is_kept() {
        let report = report("Trusted");

        assert_eq!(report.actions.len(), 1);
        assert_eq!(report.actions[0].action, "c2pa.created");
        assert_eq!(report.ingredients.len(), 1);
        assert_eq!(report.ingredients[0].title.as_deref(), Some("base.jpg"));
    }

    #[test]
    fn the_organization_is_lifted_out_of_the_certificate_subject() {
        let report = report("Trusted");
        let signer = report.signer.expect("a signature_info means a signer");

        assert_eq!(signer.organization.as_deref(), Some("OpenAI Inc."));
        assert_eq!(signer.cert_serial.as_deref(), Some("42"));
    }

    #[test]
    fn a_subject_without_an_organization_falls_back_to_the_whole_name() {
        assert_eq!(organization_of("CN=Example Only"), "CN=Example Only");
        assert_eq!(organization_of("CN=A, O=Example Inc."), "Example Inc.");
        assert_eq!(organization_of(""), "");
    }

    #[test]
    fn the_signing_algorithm_is_reported_in_lower_case() {
        let report = report("Trusted");

        assert_eq!(
            report
                .claim
                .expect("a manifest carries a claim")
                .algorithm
                .as_deref(),
            Some("ps256")
        );
    }

    #[test]
    fn untrusted_arrives_as_a_warning_and_success_codes_are_dropped() {
        let report = report("Valid");

        assert_eq!(report.credential.status, CredentialStatus::ValidUntrusted);
        assert_eq!(report.validation.warnings.len(), 1);
        assert_eq!(
            report.validation.warnings[0].code,
            "signingCredential.untrusted"
        );
        assert!(report.validation.errors.is_empty());
    }

    #[test]
    fn an_untrusted_signer_is_never_labelled_as_listed() {
        let report = report("Valid");

        assert_eq!(
            report.signer.and_then(|s| s.on_trust_list).as_deref(),
            Some("none")
        );
    }

    #[test]
    fn every_selector_names_the_list_it_judged_against() {
        let cases = [
            (TrustSelector::Official, "official"),
            (TrustSelector::Both, "official"),
            (TrustSelector::Interim, "interim"),
            (TrustSelector::None, "none"),
        ];

        for (selector, expected) in cases {
            let report = build(
                store("Trusted"),
                engine(),
                asset(),
                &Options::default(),
                selector,
            );

            assert_eq!(
                report.signer.and_then(|s| s.on_trust_list).as_deref(),
                Some(expected),
                "selector {selector:?}"
            );
        }
    }

    #[test]
    fn the_raw_store_travels_only_when_asked_for() {
        let quiet = report("Trusted");
        assert!(quiet.raw_manifest_store.is_none());

        let loud = build(
            store("Trusted"),
            engine(),
            asset(),
            &Options {
                include_raw: true,
                ..Options::default()
            },
            TrustSelector::Official,
        );
        assert_eq!(
            loud.raw_manifest_store.expect("asked for the raw store"),
            store("Trusted")
        );
    }

    #[test]
    fn a_store_without_manifests_still_produces_a_report() {
        let report = build(
            serde_json::json!({"validation_state": "Valid"}),
            engine(),
            asset(),
            &Options::default(),
            TrustSelector::Official,
        );

        assert!(report.signer.is_none());
        assert!(report.claim.is_none());
        assert!(report.actions.is_empty());
        assert!(report.ingredients.is_empty());
        assert_eq!(report.source.category, SourceCategory::Unknown);
    }

    #[test]
    fn an_unlabelled_active_manifest_falls_back_to_the_first_one() {
        let store = serde_json::json!({
            "validation_state": "Valid",
            "manifests": {"urn:only": {"claim_generator": "Leica M11"}}
        });

        let report = build(
            store,
            engine(),
            asset(),
            &Options::default(),
            TrustSelector::Official,
        );

        assert_eq!(
            report.claim.and_then(|c| c.generator).as_deref(),
            Some("Leica M11")
        );
    }

    #[test]
    fn the_ingredient_cap_comes_from_the_caller() {
        let mut items = Vec::new();
        for index in 0..10 {
            items.push(serde_json::json!({"title": format!("{index}.jpg")}));
        }
        let store = serde_json::json!({
            "validation_state": "Valid",
            "active_manifest": "urn:one",
            "manifests": {"urn:one": {"ingredients": items}}
        });

        let report = build(
            store,
            engine(),
            asset(),
            &Options {
                max_ingredients: 3,
                ..Options::default()
            },
            TrustSelector::Official,
        );

        assert_eq!(report.ingredients.len(), 3);
    }

    #[test]
    fn an_ingredient_without_a_manifest_reads_as_absent() {
        let store = serde_json::json!({
            "validation_state": "Valid",
            "active_manifest": "urn:one",
            "manifests": {"urn:one": {"ingredients": [
                {"title": "plain.jpg"},
                {"title": "signed.jpg", "active_manifest": "urn:two"},
                {"title": "broken.jpg", "c2pa_manifest": "urn:three",
                 "validation_status": [{"code": "assertion.dataHash.mismatch"}]}
            ]}}
        });

        let report = build(
            store,
            engine(),
            asset(),
            &Options::default(),
            TrustSelector::Official,
        );

        let statuses: Vec<_> = report
            .ingredients
            .iter()
            .map(|item| item.credential_status)
            .collect();

        assert_eq!(
            statuses,
            vec![
                Some(CredentialStatus::Absent),
                Some(CredentialStatus::ValidUntrusted),
                Some(CredentialStatus::PresentInvalid),
            ]
        );
    }

    #[test]
    fn a_repeated_code_is_reported_once() {
        let store = serde_json::json!({
            "validation_state": "Invalid",
            "validation_status": [
                {"code": "assertion.dataHash.mismatch"},
                {"code": "assertion.dataHash.mismatch"}
            ],
            "validation_results": {"activeManifest": {
                "failure": [{"code": "assertion.dataHash.mismatch"}]
            }}
        });

        let report = build(
            store,
            engine(),
            asset(),
            &Options::default(),
            TrustSelector::Official,
        );

        assert_eq!(report.validation.errors.len(), 1);
    }

    #[test]
    fn a_flood_of_distinct_codes_cannot_grow_the_report_without_bound() {
        let mut failures = Vec::new();
        for index in 0..(MAX_DISTINCT_CODES * 4) {
            failures.push(serde_json::json!({"code": format!("synthetic.code.{index}")}));
        }
        let store = serde_json::json!({
            "validation_state": "Invalid",
            "validation_results": {"activeManifest": {"failure": failures}}
        });

        let report = build(
            store,
            engine(),
            asset(),
            &Options::default(),
            TrustSelector::Official,
        );

        assert_eq!(report.validation.errors.len(), MAX_ENTRIES);
    }

    #[test]
    fn an_iptc_assertion_is_read_when_the_action_carries_no_source_type() {
        let store = serde_json::json!({
            "validation_state": "Valid",
            "active_manifest": "urn:one",
            "manifests": {"urn:one": {"assertions": [{
                "label": "stds.iptc.photo-metadata",
                "data": {"Iptc4xmpExt:DigitalSourceType":
                    "http://cv.iptc.org/newscodes/digitalsourcetype/digitalCapture"}
            }]}}
        });

        let report = build(
            store,
            engine(),
            asset(),
            &Options::default(),
            TrustSelector::Official,
        );

        assert_eq!(report.source.category, SourceCategory::Camera);
    }

    #[test]
    fn the_generator_is_only_consulted_when_nothing_was_declared() {
        let store = serde_json::json!({
            "validation_state": "Valid",
            "active_manifest": "urn:one",
            "manifests": {"urn:one": {"claim_generator": "Midjourney v7"}}
        });

        let report = build(
            store,
            engine(),
            asset(),
            &Options::default(),
            TrustSelector::Official,
        );

        assert_eq!(report.source.category, SourceCategory::AiGenerated);
        assert!(report.source.digital_source_type.is_none());
    }

    #[test]
    fn the_action_list_is_capped() {
        let mut actions = Vec::new();
        for index in 0..(MAX_ACTIONS * 2) {
            actions.push(serde_json::json!({"action": format!("c2pa.edited.{index}")}));
        }
        let store = serde_json::json!({
            "validation_state": "Valid",
            "active_manifest": "urn:one",
            "manifests": {"urn:one": {"assertions": [{
                "label": "c2pa.actions.v2",
                "data": {"actions": actions}
            }]}}
        });

        let report = build(
            store,
            engine(),
            asset(),
            &Options::default(),
            TrustSelector::Official,
        );

        assert_eq!(report.actions.len(), MAX_ACTIONS);
    }
}

use std::collections::HashSet;

use serde_json::Value;

use crate::classify;
use crate::explain;
use crate::report::{
    Action, Asset, Claim, Credential, CredentialStatus, EngineInfo, Ingredient, Origin,
    OriginStatus, Report, Signer, Source, SourceCategory, TrustSelector, Validation,
    ValidationEntry, SCHEMA_VERSION,
};
use crate::Options;

const MAX_ACTIONS: usize = 64;
const MAX_ENTRIES: usize = 64;
const MAX_TITLE_CHARS: usize = 200;
const MAX_SOURCE_DEPTH: usize = 8;
const MAX_SOURCE_MANIFESTS: usize = 512;
const RELATION_PARENT: &str = "parentOf";
const RELATION_COMPONENT: &str = "componentOf";
const MAX_DISTINCT_CODES: usize = 256;
const CODE_UNTRUSTED: &str = "signingCredential.untrusted";
pub const TRUSTED_MANIFESTS: &str = "trusted_manifests";
pub const MAX_TRUSTED_MANIFESTS: usize = MAX_SOURCE_MANIFESTS;

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
    let (source, actions) = source_and_actions(&store, active);
    let trusted_manifests = trusted_manifests(&store);
    let origin = origin(
        &store,
        active,
        &credential,
        signer.as_ref(),
        &trusted_manifests,
    );
    let ingredients = ingredients(&store, active, options.max_ingredients, &trusted_manifests);
    let validation = validation_entries(&store);

    Report {
        schema_version: SCHEMA_VERSION.to_string(),
        engine,
        credential,
        signer,
        claim,
        source,
        origin,
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
        title: text(manifest.get("title"))
            .map(|title| title.chars().take(MAX_TITLE_CHARS).collect()),
        spec_version: text(manifest.get("claim_version"))
            .or_else(|| text(manifest.get("spec_version"))),
        signed_at: signature.and_then(|info| text(info.get("time"))),
        timestamp_authority: signature.and_then(|info| text(info.get("time_authority"))),
        algorithm: signature
            .and_then(|info| text(info.get("alg")))
            .map(|alg| alg.to_lowercase()),
    })
}

fn source_and_actions(store: &Value, active: Option<&Value>) -> (Source, Vec<Action>) {
    let Some(manifest) = active else {
        return (Source::unknown(), Vec::new());
    };
    let mut budget = MAX_SOURCE_MANIFESTS;

    (
        resolved_source(store, manifest, MAX_SOURCE_DEPTH, &mut budget),
        actions(manifest),
    )
}

fn assertions(manifest: &Value) -> impl Iterator<Item = (&str, Option<&Value>)> {
    manifest
        .get("assertions")
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or_default()
        .iter()
        .map(|assertion| {
            (
                assertion.get("label").and_then(Value::as_str).unwrap_or(""),
                assertion.get("data"),
            )
        })
}

fn action_entries(manifest: &Value) -> impl Iterator<Item = &Value> {
    assertions(manifest)
        .filter(|(label, _)| label.starts_with("c2pa.actions"))
        .flat_map(|(_, data)| {
            data.and_then(|d| d.get("actions"))
                .and_then(Value::as_array)
                .map(Vec::as_slice)
                .unwrap_or_default()
        })
}

fn actions(manifest: &Value) -> Vec<Action> {
    action_entries(manifest)
        .filter_map(|entry| {
            let name = entry.get("action").and_then(Value::as_str)?;

            Some(Action {
                action: name.to_string(),
                when: text(entry.get("when")),
                software: text(entry.get("softwareAgent")).or_else(|| {
                    entry
                        .get("softwareAgent")
                        .and_then(|agent| text(agent.get("name")))
                }),
            })
        })
        .take(MAX_ACTIONS)
        .collect()
}

fn declared_source(manifest: &Value) -> Source {
    let from_actions = action_entries(manifest)
        .filter_map(|entry| entry.get("digitalSourceType").and_then(Value::as_str));
    let from_iptc = assertions(manifest)
        .filter(|(label, _)| label.starts_with("stds.iptc"))
        .filter_map(|(_, data)| {
            data.and_then(|d| {
                d.get("digitalSourceType")
                    .or_else(|| d.get("Iptc4xmpExt:DigitalSourceType"))
            })
            .and_then(Value::as_str)
        });

    from_actions
        .chain(from_iptc)
        .fold(Source::unknown(), |mut source, uri| {
            if let Some(found) = classify::category_of(uri) {
                source.category = classify::strongest(source.category, found);
                source.digital_source_type = Some(uri.to_string());
            }
            source
        })
}

fn generator_source(manifest: &Value) -> Option<SourceCategory> {
    let generator = manifest
        .get("claim_generator_info")
        .and_then(Value::as_array)
        .and_then(|list| list.first())
        .and_then(|first| first.get("name"))
        .and_then(Value::as_str)
        .filter(|name| !name.is_empty())
        .or_else(|| manifest.get("claim_generator").and_then(Value::as_str))
        .unwrap_or("");

    classify::from_generator(generator)
}

fn strongest_ingredient(
    store: &Value,
    manifest: &Value,
    relationship: &str,
    depth: usize,
    budget: &mut usize,
) -> Source {
    let mut strongest = Source::unknown();
    if depth == 0 {
        return strongest;
    }

    for item in manifest
        .get("ingredients")
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or_default()
    {
        if *budget == 0 {
            break;
        }
        let related = item.get("relationship").and_then(Value::as_str) == Some(relationship);
        let valid = ingredient_status(item) == Some(CredentialStatus::ValidUntrusted);
        let origin = item
            .get("active_manifest")
            .and_then(Value::as_str)
            .and_then(|label| store.get("manifests")?.get(label));
        let Some(origin) = origin.filter(|_| related && valid) else {
            continue;
        };
        *budget -= 1;

        let found = resolved_source(store, origin, depth - 1, budget);
        if classify::strongest(strongest.category, found.category) != strongest.category {
            strongest = found;
        }
    }

    strongest
}

fn resolved_source(store: &Value, manifest: &Value, depth: usize, budget: &mut usize) -> Source {
    let own = declared_source(manifest);
    let parent = strongest_ingredient(store, manifest, RELATION_PARENT, depth, budget);
    let component = strongest_ingredient(store, manifest, RELATION_COMPONENT, depth, budget);

    let composite = own.category == SourceCategory::Unknown
        || own
            .digital_source_type
            .as_deref()
            .is_some_and(classify::is_plain_composite);
    let mut source =
        if own.category == SourceCategory::Unknown && parent.category != SourceCategory::Unknown {
            Source {
                inherited: true,
                ..parent
            }
        } else {
            own
        };
    if composite && classify::is_ai(component.category) {
        let raised = classify::strongest(source.category, SourceCategory::AiComposite);
        source.inherited = source.inherited || raised != source.category;
        source.category = raised;
    }
    if source.category == SourceCategory::Unknown {
        source.category = generator_source(manifest).unwrap_or(SourceCategory::Unknown);
    }

    source
}

fn trusted_manifests(store: &Value) -> HashSet<&str> {
    store
        .get(TRUSTED_MANIFESTS)
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or_default()
        .iter()
        .filter_map(Value::as_str)
        .collect()
}

fn ingredient_items(manifest: &Value) -> &[Value] {
    manifest
        .get("ingredients")
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or_default()
}

fn ingredient_manifest<'a>(store: &'a Value, item: &'a Value) -> Option<(&'a str, &'a Value)> {
    let label = item.get("active_manifest").and_then(Value::as_str)?;

    Some((label, store.get("manifests")?.get(label)?))
}

fn signer_name(manifest: &Value) -> Option<String> {
    let info = manifest.get("signature_info")?;

    text(info.get("issuer"))
        .as_deref()
        .map(organization_of)
        .or_else(|| text(info.get("common_name")))
}

struct TrustedSigner {
    depth: u32,
    signer_name: Option<String>,
    relationship: String,
}

fn nearer(a: Option<TrustedSigner>, b: Option<TrustedSigner>) -> Option<TrustedSigner> {
    match (a, b) {
        (Some(a), Some(b)) if b.depth < a.depth => Some(b),
        (Some(a), _) => Some(a),
        (None, b) => b,
    }
}

fn nearest_trusted(
    store: &Value,
    manifest: &Value,
    trusted: &HashSet<&str>,
    depth: usize,
    budget: &mut usize,
) -> Option<TrustedSigner> {
    if depth == 0 {
        return None;
    }
    let mut parent = None;
    let mut component = None;
    let mut component_invalid = false;

    for item in ingredient_items(manifest) {
        let relationship = item.get("relationship").and_then(Value::as_str);
        let is_component = relationship == Some(RELATION_COMPONENT);
        if !is_component && relationship != Some(RELATION_PARENT) {
            continue;
        }
        let status = ingredient_status(item);
        if status == Some(CredentialStatus::PresentInvalid) {
            component_invalid |= is_component;
            continue;
        }
        let Some((label, origin)) = ingredient_manifest(store, item)
            .filter(|_| status == Some(CredentialStatus::ValidUntrusted) && *budget > 0)
        else {
            continue;
        };
        *budget -= 1;

        let found = if trusted.contains(label) {
            Some(TrustedSigner {
                depth: 1,
                signer_name: signer_name(origin),
                relationship: relationship.unwrap_or_default().to_string(),
            })
        } else {
            nearest_trusted(store, origin, trusted, depth - 1, budget).map(|hit| TrustedSigner {
                depth: hit.depth + 1,
                ..hit
            })
        };
        if is_component {
            component = nearer(component, found);
        } else {
            parent = nearer(parent, found);
        }
    }
    if component_invalid {
        component = None;
    }

    nearer(parent, component)
}

fn origin(
    store: &Value,
    active: Option<&Value>,
    credential: &Credential,
    signer: Option<&Signer>,
    trusted: &HashSet<&str>,
) -> Origin {
    if !credential.valid {
        return Origin::default();
    }
    if credential.trusted {
        return Origin {
            status: OriginStatus::Traced,
            signer_name: signer
                .and_then(|s| s.organization.clone().or_else(|| s.common_name.clone())),
            relationship: None,
            depth: Some(0),
        };
    }
    let mut budget = MAX_SOURCE_MANIFESTS;

    active
        .and_then(|manifest| {
            nearest_trusted(store, manifest, trusted, MAX_SOURCE_DEPTH, &mut budget)
        })
        .map_or_else(Origin::untraced, |hit| Origin {
            status: OriginStatus::Traced,
            signer_name: hit.signer_name,
            relationship: Some(hit.relationship),
            depth: Some(hit.depth),
        })
}

fn ingredients(
    store: &Value,
    active: Option<&Value>,
    limit: usize,
    trusted: &HashSet<&str>,
) -> Vec<Ingredient> {
    let Some(manifest) = active else {
        return Vec::new();
    };

    ingredient_items(manifest)
        .iter()
        .take(limit)
        .map(|item| {
            let origin = ingredient_manifest(store, item);
            let listed = origin.is_some_and(|(label, _)| trusted.contains(label));
            let status = match ingredient_status(item) {
                Some(CredentialStatus::ValidUntrusted) if listed => {
                    Some(CredentialStatus::ValidTrusted)
                }
                other => other,
            };

            Ingredient {
                title: text(item.get("title")),
                relationship: text(item.get("relationship")),
                credential_status: status,
                signer_name: origin.and_then(|(_, found)| signer_name(found)),
            }
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
        .map(Vec::as_slice)
        .unwrap_or_default()
        .iter()
        .any(|entry| entry.get("code").and_then(Value::as_str) != Some(CODE_UNTRUSTED));
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
                    let warning = entry
                        .get("code")
                        .and_then(Value::as_str)
                        .is_some_and(explain::is_warning);
                    if name != "informational" || warning {
                        consider(entry, &mut out, &mut seen);
                    }
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

    const AI_GENERATED: &str =
        "http://cv.iptc.org/newscodes/digitalsourcetype/trainedAlgorithmicMedia";
    const CAPTURED: &str = "http://cv.iptc.org/newscodes/digitalsourcetype/digitalCapture";
    const COMPOSITE: &str = "http://cv.iptc.org/newscodes/digitalsourcetype/composite";

    fn manifest(declared: Option<&str>, ingredients: Value) -> Value {
        let mut action = serde_json::json!({"action": "c2pa.opened"});
        if let Some(uri) = declared {
            action["digitalSourceType"] = Value::from(uri);
        }

        serde_json::json!({
            "claim_generator_info": [{"name": "c2pa-check carry", "version": "1"}],
            "assertions": [{"label": "c2pa.actions.v2", "data": {"actions": [action]}}],
            "ingredients": ingredients
        })
    }

    fn ingredient(relationship: &str, label: &str) -> Value {
        serde_json::json!({"relationship": relationship, "active_manifest": label})
    }

    fn source_of(manifests: Value) -> Source {
        let store = serde_json::json!({
            "active_manifest": "urn:active",
            "validation_state": "Valid",
            "manifests": manifests
        });

        build(
            store,
            engine(),
            asset(),
            &Options::default(),
            TrustSelector::Official,
        )
        .source
    }

    #[test]
    fn a_carried_file_inherits_the_declared_source_of_its_parent() {
        let source = source_of(serde_json::json!({
            "urn:active": manifest(None, serde_json::json!([ingredient("parentOf", "urn:parent")])),
            "urn:parent": manifest(Some(AI_GENERATED), serde_json::json!([]))
        }));

        assert_eq!(source.category, SourceCategory::AiGenerated);
        assert_eq!(source.digital_source_type.as_deref(), Some(AI_GENERATED));
        assert!(source.inherited);
    }

    #[test]
    fn a_source_the_file_declares_itself_wins_over_its_parent() {
        let source = source_of(serde_json::json!({
            "urn:active": manifest(Some(CAPTURED), serde_json::json!([ingredient("parentOf", "urn:parent")])),
            "urn:parent": manifest(Some(AI_GENERATED), serde_json::json!([]))
        }));

        assert_eq!(source.category, SourceCategory::Camera);
        assert_eq!(source.digital_source_type.as_deref(), Some(CAPTURED));
        assert!(!source.inherited);
    }

    #[test]
    fn a_parent_whose_credential_does_not_validate_or_is_missing_is_not_followed() {
        let mut invalid = ingredient("parentOf", "urn:parent");
        invalid["validation_status"] = serde_json::json!([{"code": "assertion.dataHash.mismatch"}]);
        let parent = manifest(Some(AI_GENERATED), serde_json::json!([]));

        let failed = source_of(serde_json::json!({
            "urn:active": manifest(None, serde_json::json!([invalid])),
            "urn:parent": parent
        }));
        let missing = source_of(serde_json::json!({
            "urn:active": manifest(None, serde_json::json!([ingredient("parentOf", "urn:gone")]))
        }));
        let unsigned = source_of(serde_json::json!({
            "urn:active": manifest(None, serde_json::json!([{"relationship": "parentOf", "title": "a.png"}]))
        }));

        for source in [failed, missing, unsigned] {
            assert_eq!(source.category, SourceCategory::Unknown);
            assert_eq!(source.digital_source_type, None);
            assert!(!source.inherited);
        }
    }

    fn chain(length: usize) -> Value {
        let mut manifests = serde_json::Map::new();
        for index in 0..length {
            let label = if index == 0 {
                "urn:active".to_string()
            } else {
                format!("urn:{index}")
            };
            let next = serde_json::json!([ingredient("parentOf", &format!("urn:{}", index + 1))]);
            manifests.insert(label, manifest(None, next));
        }
        manifests.insert(
            format!("urn:{length}"),
            manifest(Some(AI_GENERATED), serde_json::json!([])),
        );

        Value::Object(manifests)
    }

    #[test]
    fn the_parent_chain_is_followed_to_a_fixed_depth_and_a_cycle_ends() {
        let near = source_of(chain(MAX_SOURCE_DEPTH));
        let far = source_of(chain(MAX_SOURCE_DEPTH + 1));
        let cycle = source_of(serde_json::json!({
            "urn:active": manifest(None, serde_json::json!([ingredient("parentOf", "urn:active")]))
        }));

        assert_eq!(near.category, SourceCategory::AiGenerated);
        assert!(near.inherited);
        assert_eq!(far.category, SourceCategory::Unknown);
        assert!(!far.inherited);
        assert_eq!(cycle.category, SourceCategory::Unknown);
    }

    #[test]
    fn a_parent_known_only_by_its_generator_name_is_inherited_too() {
        let mut parent = manifest(None, serde_json::json!([]));
        parent["claim_generator_info"] = serde_json::json!([{"name": "OpenAI Media Service API"}]);

        let source = source_of(serde_json::json!({
            "urn:active": manifest(None, serde_json::json!([ingredient("parentOf", "urn:parent")])),
            "urn:parent": parent
        }));

        assert_eq!(source.category, SourceCategory::AiGenerated);
        assert_eq!(source.digital_source_type, None);
        assert!(source.inherited);
    }

    #[test]
    fn a_composite_with_an_ai_component_is_an_ai_composite() {
        let direct = source_of(serde_json::json!({
            "urn:active": manifest(Some(COMPOSITE), serde_json::json!([
                ingredient("componentOf", "urn:photo"),
                ingredient("componentOf", "urn:generated")
            ])),
            "urn:photo": manifest(Some(CAPTURED), serde_json::json!([])),
            "urn:generated": manifest(Some(AI_GENERATED), serde_json::json!([]))
        }));
        let behind_a_carry = source_of(serde_json::json!({
            "urn:active": manifest(Some(COMPOSITE), serde_json::json!([ingredient("componentOf", "urn:carried")])),
            "urn:carried": manifest(None, serde_json::json!([ingredient("parentOf", "urn:generated")])),
            "urn:generated": manifest(Some(AI_GENERATED), serde_json::json!([]))
        }));
        let undeclared = source_of(serde_json::json!({
            "urn:active": manifest(None, serde_json::json!([ingredient("componentOf", "urn:generated")])),
            "urn:generated": manifest(Some(AI_GENERATED), serde_json::json!([]))
        }));

        for source in [&direct, &behind_a_carry] {
            assert_eq!(source.category, SourceCategory::AiComposite);
            assert_eq!(source.digital_source_type.as_deref(), Some(COMPOSITE));
            assert!(source.inherited);
        }
        assert_eq!(undeclared.category, SourceCategory::AiComposite);
        assert_eq!(undeclared.digital_source_type, None);
        assert!(undeclared.inherited);
    }

    #[test]
    fn a_composite_without_a_valid_ai_component_keeps_what_it_declares() {
        let mut invalid = ingredient("componentOf", "urn:generated");
        invalid["validation_status"] = serde_json::json!([{"code": "claimSignature.mismatch"}]);
        let generated = manifest(Some(AI_GENERATED), serde_json::json!([]));

        let of_photos = source_of(serde_json::json!({
            "urn:active": manifest(Some(COMPOSITE), serde_json::json!([ingredient("componentOf", "urn:photo")])),
            "urn:photo": manifest(Some(CAPTURED), serde_json::json!([]))
        }));
        let of_an_invalid_component = source_of(serde_json::json!({
            "urn:active": manifest(Some(COMPOSITE), serde_json::json!([invalid])),
            "urn:generated": generated.clone()
        }));
        let declared_stronger = source_of(serde_json::json!({
            "urn:active": manifest(Some(AI_GENERATED), serde_json::json!([ingredient("componentOf", "urn:generated")])),
            "urn:generated": generated
        }));

        for source in [of_photos, of_an_invalid_component] {
            assert_eq!(source.category, SourceCategory::Software);
            assert!(!source.inherited);
        }
        assert_eq!(declared_stronger.category, SourceCategory::AiGenerated);
        assert!(!declared_stronger.inherited);
    }

    fn signed(ingredients: Value) -> Value {
        let mut out = manifest(None, ingredients);
        out["signature_info"] =
            serde_json::json!({"issuer": "Example Inc.", "common_name": "Example Signer"});

        out
    }

    fn origin_of(state: &str, trusted: &[&str], manifests: Value) -> Origin {
        let store = serde_json::json!({
            "active_manifest": "urn:active",
            "validation_state": state,
            "trusted_manifests": trusted,
            "manifests": manifests
        });

        build(
            store,
            engine(),
            asset(),
            &Options::default(),
            TrustSelector::Official,
        )
        .origin
    }

    fn invalid(mut item: Value) -> Value {
        item["validation_status"] = serde_json::json!([{"code": "assertion.dataHash.mismatch"}]);

        item
    }

    #[test]
    fn an_invalid_active_manifest_has_no_origin_even_with_a_listed_parent() {
        let origin = origin_of(
            "Invalid",
            &["urn:parent"],
            serde_json::json!({
                "urn:active": signed(serde_json::json!([ingredient("parentOf", "urn:parent")])),
                "urn:parent": signed(serde_json::json!([]))
            }),
        );

        assert_eq!(origin, Origin::default());
    }

    #[test]
    fn a_listed_parent_is_the_origin_and_an_unlisted_one_is_not() {
        let manifests = serde_json::json!({
            "urn:active": signed(serde_json::json!([ingredient("parentOf", "urn:parent")])),
            "urn:parent": signed(serde_json::json!([]))
        });

        let traced = origin_of("Valid", &["urn:parent"], manifests.clone());
        let untraced = origin_of("Valid", &[], manifests);

        assert_eq!(
            traced,
            Origin {
                status: OriginStatus::Traced,
                signer_name: Some("Example Inc.".into()),
                relationship: Some("parentOf".into()),
                depth: Some(1),
            }
        );
        assert_eq!(untraced, Origin::untraced());
    }

    #[test]
    fn an_invalid_ingredient_on_the_path_ends_it() {
        let direct = origin_of(
            "Valid",
            &["urn:parent"],
            serde_json::json!({
                "urn:active": signed(serde_json::json!([invalid(ingredient("parentOf", "urn:parent"))])),
                "urn:parent": signed(serde_json::json!([]))
            }),
        );
        let behind = origin_of(
            "Valid",
            &["urn:origin"],
            serde_json::json!({
                "urn:active": signed(serde_json::json!([ingredient("parentOf", "urn:middle")])),
                "urn:middle": signed(serde_json::json!([invalid(ingredient("parentOf", "urn:origin"))])),
                "urn:origin": signed(serde_json::json!([]))
            }),
        );

        assert_eq!(direct, Origin::untraced());
        assert_eq!(behind, Origin::untraced());
    }

    #[test]
    fn a_parent_recorded_only_as_untrusted_is_still_followed() {
        let mut item = ingredient("parentOf", "urn:parent");
        item["validation_status"] = serde_json::json!([{"code": "signingCredential.untrusted"}]);

        let origin = origin_of(
            "Valid",
            &["urn:origin"],
            serde_json::json!({
                "urn:active": signed(serde_json::json!([item])),
                "urn:parent": signed(serde_json::json!([ingredient("parentOf", "urn:origin")])),
                "urn:origin": signed(serde_json::json!([]))
            }),
        );

        assert_eq!(origin.status, OriginStatus::Traced);
        assert_eq!(origin.depth, Some(2));
    }

    #[test]
    fn a_composite_is_traced_through_a_listed_component_unless_one_is_invalid() {
        let listed = ingredient("componentOf", "urn:listed");
        let unsigned = serde_json::json!({"relationship": "componentOf", "title": "plain.png"});
        let unlisted = ingredient("componentOf", "urn:unlisted");
        let manifests = |items: Value| {
            serde_json::json!({
                "urn:active": signed(items),
                "urn:listed": signed(serde_json::json!([])),
                "urn:unlisted": signed(serde_json::json!([]))
            })
        };

        let mixed = origin_of(
            "Valid",
            &["urn:listed"],
            manifests(serde_json::json!([unsigned, unlisted, listed])),
        );
        let broken = origin_of(
            "Valid",
            &["urn:listed"],
            manifests(serde_json::json!([listed, invalid(unlisted.clone())])),
        );
        let none_listed = origin_of(
            "Valid",
            &["urn:listed"],
            manifests(serde_json::json!([unsigned, unlisted])),
        );

        assert_eq!(mixed.status, OriginStatus::Traced);
        assert_eq!(mixed.relationship.as_deref(), Some("componentOf"));
        assert_eq!(mixed.depth, Some(1));
        assert_eq!(broken, Origin::untraced());
        assert_eq!(none_listed, Origin::untraced());
    }

    #[test]
    fn the_nearest_listed_signer_is_reported_and_the_walk_stops_at_the_depth_limit() {
        let label = format!("urn:{MAX_SOURCE_DEPTH}");
        let beyond = format!("urn:{}", MAX_SOURCE_DEPTH + 1);

        let near = origin_of("Valid", &[&label, "urn:2"], chain(MAX_SOURCE_DEPTH));
        let at_limit = origin_of("Valid", &[&label], chain(MAX_SOURCE_DEPTH));
        let far = origin_of("Valid", &[&beyond], chain(MAX_SOURCE_DEPTH + 1));
        let cycle = origin_of(
            "Valid",
            &[],
            serde_json::json!({
                "urn:active": manifest(None, serde_json::json!([ingredient("parentOf", "urn:active")]))
            }),
        );

        assert_eq!(near.depth, Some(2));
        assert_eq!(at_limit.status, OriginStatus::Traced);
        assert_eq!(at_limit.depth, Some(MAX_SOURCE_DEPTH as u32));
        assert_eq!(far, Origin::untraced());
        assert_eq!(cycle, Origin::untraced());
    }

    #[test]
    fn a_trusted_active_manifest_is_its_own_origin() {
        let origin = report("Trusted").origin;

        assert_eq!(origin.status, OriginStatus::Traced);
        assert_eq!(origin.depth, Some(0));
        assert_eq!(origin.signer_name.as_deref(), Some("OpenAI Inc."));
        assert_eq!(origin.relationship, None);
        assert_eq!(report("Valid").origin, Origin::untraced());
        assert_eq!(report("Invalid").origin, Origin::default());
    }

    #[test]
    fn an_ingredient_names_its_signer_and_reads_trusted_when_listed() {
        let store = serde_json::json!({
            "active_manifest": "urn:active",
            "validation_state": "Valid",
            "trusted_manifests": ["urn:listed"],
            "manifests": {
                "urn:active": signed(serde_json::json!([
                    ingredient("parentOf", "urn:listed"),
                    ingredient("componentOf", "urn:unlisted"),
                    invalid(ingredient("componentOf", "urn:listed")),
                    {"relationship": "componentOf"}
                ])),
                "urn:listed": signed(serde_json::json!([])),
                "urn:unlisted": {"signature_info": {"common_name": "Only A Name"}}
            }
        });

        let report = build(
            store,
            engine(),
            asset(),
            &Options::default(),
            TrustSelector::Official,
        );
        let seen: Vec<_> = report
            .ingredients
            .iter()
            .map(|item| (item.credential_status, item.signer_name.as_deref()))
            .collect();

        assert_eq!(
            seen,
            [
                (Some(CredentialStatus::ValidTrusted), Some("Example Inc.")),
                (Some(CredentialStatus::ValidUntrusted), Some("Only A Name")),
                (Some(CredentialStatus::PresentInvalid), Some("Example Inc.")),
                (Some(CredentialStatus::Absent), None),
            ]
        );
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
    fn an_informational_code_is_dropped_unless_we_report_it_as_a_warning() {
        let store = serde_json::json!({
            "validation_state": "Valid",
            "validation_results": {"activeManifest": {
                "informational": [
                    {"code": "signingCredential.ocsp.skipped"},
                    {"code": "timeStamp.untrusted"}
                ],
                "failure": [{"code": "signingCredential.untrusted"}]
            }}
        });

        let report = build(
            store,
            engine(),
            asset(),
            &Options::default(),
            TrustSelector::Official,
        );

        assert!(report.validation.errors.is_empty());
        let warnings: Vec<_> = report
            .validation
            .warnings
            .iter()
            .map(|w| w.code.as_str())
            .collect();
        assert_eq!(
            warnings,
            ["timeStamp.untrusted", "signingCredential.untrusted"]
        );
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

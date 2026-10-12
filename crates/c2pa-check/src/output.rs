use std::io::Write;

use c2pa_check_core::{CredentialStatus, Report, SourceCategory};

use crate::{Format, Gate};

const MIXED_METRICS: &str = "mixed";

pub fn render(
    format: Format,
    results: &[(String, Option<Report>)],
    gates: &[Gate],
    color: bool,
    mut out: &mut dyn Write,
) -> anyhow::Result<()> {
    match format {
        Format::Text => {
            for (target, report) in results {
                text(&mut out, target, report.as_ref(), color)?;
            }
            if results.len() > 1 {
                summary(&mut out, results, gates)?;
            }
        }
        Format::Json => {
            let documents: Vec<_> = (0..results.len())
                .map(|index| document(results, gates, index))
                .collect();
            serde_json::to_writer_pretty(&mut out, &documents)?;
            writeln!(out)?;
        }
        Format::Ndjson => {
            for index in 0..results.len() {
                serde_json::to_writer(&mut out, &document(results, gates, index))?;
                writeln!(out)?;
            }
        }
        Format::Junit => junit(&mut out, results, gates)?,
    }

    Ok(())
}

fn gate(gates: &[Gate], index: usize) -> Gate {
    gates.get(index).copied().unwrap_or_default()
}

fn covered(gate: Gate, report: Option<&Report>) -> bool {
    report.is_some_and(|r| gate.metric.counts(r))
}

fn document(
    results: &[(String, Option<Report>)],
    gates: &[Gate],
    index: usize,
) -> serde_json::Value {
    let (target, report) = &results[index];
    let gate = gate(gates, index);

    serde_json::json!({
        "target": target,
        "result": report,
        "coverage": {
            "metric": gate.metric.as_str(),
            "expected": gate.expected,
            "covered": gate.expected && covered(gate, report.as_ref()),
        },
    })
}

fn metric_label(gates: &[Gate], count: usize) -> &'static str {
    let first = gate(gates, 0).metric;
    if (1..count).all(|index| gate(gates, index).metric == first) {
        first.as_str()
    } else {
        MIXED_METRICS
    }
}

const RESET: &str = "\x1b[0m";
const MAX_LISTED_MISSING: usize = 20;

fn tint(status: CredentialStatus) -> &'static str {
    match status {
        CredentialStatus::Absent | CredentialStatus::Error => "\x1b[90m",
        CredentialStatus::PresentInvalid => "\x1b[31m",
        CredentialStatus::ValidUntrusted => "\x1b[33m",
        CredentialStatus::ValidTrusted => "\x1b[32m",
    }
}

fn category(category: SourceCategory) -> &'static str {
    match category {
        SourceCategory::AiGenerated => "AI generated",
        SourceCategory::AiComposite => "AI composite",
        SourceCategory::AiEnhanced => "AI enhanced",
        SourceCategory::Algorithmic => "algorithmic",
        SourceCategory::Software => "software",
        SourceCategory::Camera => "camera capture",
        SourceCategory::Unknown => "not declared",
    }
}

fn text(
    out: &mut impl Write,
    target: &str,
    report: Option<&Report>,
    color: bool,
) -> anyhow::Result<()> {
    writeln!(out, "{target}")?;

    let Some(report) = report else {
        writeln!(out, "  Content Credentials   COULD NOT BE READ")?;

        return Ok(());
    };

    let reset = if color { RESET } else { "" };
    let tint = if color {
        tint(report.credential.status)
    } else {
        ""
    };

    let present = if report.credential.present {
        "PRESENT"
    } else {
        "ABSENT"
    };
    writeln!(out, "  Content Credentials   {tint}{present}{reset}")?;

    if report.credential.present {
        let manifest = if report.credential.valid {
            "VALID"
        } else {
            "INVALID"
        };
        writeln!(out, "  Manifest              {tint}{manifest}{reset}")?;

        let trust = if report.credential.trusted {
            format!("TRUSTED ({})", report.engine.trust_list_version)
        } else {
            "NOT ON THE TRUST LIST".to_string()
        };
        writeln!(out, "  Trust                 {tint}{trust}{reset}")?;

        if let Some(signer) = &report.signer {
            let name = signer
                .organization
                .as_deref()
                .or(signer.common_name.as_deref())
                .unwrap_or("unknown");
            let issuer = signer.issuer.as_deref().unwrap_or("unknown issuer");
            writeln!(out, "  Signer                {name} · {issuer}")?;
        }
        if let (Some(depth), Some(name)) = (
            report.origin.depth.filter(|depth| *depth > 0),
            report.origin.signer_name.as_deref(),
        ) {
            writeln!(
                out,
                "  Origin                TRACED to {name}, {depth} ingredient step(s) back"
            )?;
        }
    }

    writeln!(
        out,
        "  Digital source        {}",
        report
            .source
            .digital_source_type
            .as_deref()
            .map(|uri| uri.rsplit('/').next().unwrap_or(uri).to_string())
            .map(|slug| format!("{slug} ({})", category(report.source.category)))
            .unwrap_or_else(|| category(report.source.category).to_string())
    )?;

    if !report.actions.is_empty() {
        let names: Vec<_> = report.actions.iter().map(|a| a.action.as_str()).collect();
        writeln!(out, "  Actions               {}", names.join(", "))?;
    }
    for warning in &report.validation.warnings {
        writeln!(out, "  Warning               {}", warning.code)?;
    }
    for error in &report.validation.errors {
        writeln!(out, "  Error                 {}", error.code)?;
    }
    writeln!(out)?;

    Ok(())
}

fn coverage(results: &[(String, Option<Report>)], gates: &[Gate]) -> f64 {
    let expected: Vec<usize> = (0..results.len())
        .filter(|index| gate(gates, *index).expected)
        .collect();
    if expected.is_empty() {
        return 0.0;
    }

    let counted = expected
        .iter()
        .filter(|index| covered(gate(gates, **index), results[**index].1.as_ref()))
        .count();

    counted as f64 / expected.len() as f64 * 100.0
}

fn summary(
    out: &mut impl Write,
    results: &[(String, Option<Report>)],
    gates: &[Gate],
) -> anyhow::Result<()> {
    let total = results.len();
    let trusted = results
        .iter()
        .filter(|(_, r)| {
            r.as_ref()
                .is_some_and(|r| r.credential.status == CredentialStatus::ValidTrusted)
        })
        .count();
    let missing: Vec<_> = results
        .iter()
        .enumerate()
        .filter(|(index, (_, r))| {
            gate(gates, *index).expected
                && r.as_ref()
                    .is_some_and(|r| r.credential.status == CredentialStatus::Absent)
        })
        .map(|(_, (target, _))| target.as_str())
        .collect();

    writeln!(
        out,
        "{total} scanned · {trusted} trusted · {} missing",
        missing.len()
    )?;
    for target in missing.iter().take(MAX_LISTED_MISSING) {
        writeln!(out, "  missing: {target}")?;
    }
    if missing.len() > MAX_LISTED_MISSING {
        writeln!(out, "  … and {} more", missing.len() - MAX_LISTED_MISSING)?;
    }
    writeln!(
        out,
        "coverage {:.1}% {}   monitor production provenance at https://c2pa.design",
        coverage(results, gates),
        metric_label(gates, results.len())
    )?;

    Ok(())
}

fn junit(
    out: &mut impl Write,
    results: &[(String, Option<Report>)],
    gates: &[Gate],
) -> anyhow::Result<()> {
    let passes = |index: usize, report: &Report| {
        let gate = gate(gates, index);

        !gate.expected || gate.metric.counts(report)
    };
    let failures = results
        .iter()
        .enumerate()
        .filter(|(index, (_, r))| r.as_ref().is_some_and(|r| !passes(*index, r)))
        .count();

    writeln!(out, r#"<?xml version="1.0" encoding="UTF-8"?>"#)?;
    writeln!(
        out,
        r#"<testsuite name="c2pa-check" tests="{}" failures="{}">"#,
        results.len(),
        failures
    )?;
    writeln!(out, "  <properties>")?;
    writeln!(
        out,
        r#"    <property name="coverage_metric" value="{}"/>"#,
        metric_label(gates, results.len())
    )?;
    writeln!(
        out,
        r#"    <property name="coverage" value="{:.1}"/>"#,
        coverage(results, gates)
    )?;
    writeln!(out, "  </properties>")?;
    for (index, (target, report)) in results.iter().enumerate() {
        let name = escape(target);
        match report {
            Some(r) if passes(index, r) => {
                writeln!(out, r#"  <testcase name="{name}"/>"#)?;
            }
            Some(r) => {
                writeln!(out, r#"  <testcase name="{name}">"#)?;
                writeln!(
                    out,
                    r#"    <failure message="{}">credential.status is {}, origin.status is {}; not {}</failure>"#,
                    escape(r.credential.status.as_str()),
                    escape(r.credential.status.as_str()),
                    r.origin.status.as_str(),
                    gate(gates, index).metric.as_str()
                )?;
                writeln!(out, "  </testcase>")?;
            }
            None => {
                writeln!(out, r#"  <testcase name="{name}">"#)?;
                writeln!(out, r#"    <error message="unreadable"/>"#)?;
                writeln!(out, "  </testcase>")?;
            }
        }
    }
    writeln!(out, "</testsuite>")?;

    Ok(())
}

fn escape(value: &str) -> String {
    let mut out = String::with_capacity(value.len());

    for character in value.chars() {
        match character {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\t' | '\n' | '\r' => out.push(' '),
            other if (other as u32) < 0x20 => out.push('?'),
            other => out.push(other),
        }
    }

    out
}

pub fn tree(target: &str, report: &Report) {
    println!("{target}");
    println!("├─ credential   {}", report.credential.status.as_str());
    println!(
        "├─ trust list   {} ({})",
        report.engine.trust_list_version, report.engine.name
    );
    if let Some(claim) = &report.claim {
        println!(
            "├─ claim        {} · {}",
            claim.generator.as_deref().unwrap_or("unknown generator"),
            claim.algorithm.as_deref().unwrap_or("unknown algorithm")
        );
    }
    if let Some(signer) = &report.signer {
        println!(
            "├─ signature    {} · {}",
            signer.organization.as_deref().unwrap_or("unknown"),
            signer.issuer.as_deref().unwrap_or("unknown issuer")
        );
    }
    println!("├─ source       {}", category(report.source.category));
    for action in &report.actions {
        println!("│  ├─ action    {}", action.action);
    }
    for ingredient in &report.ingredients {
        println!(
            "│  ├─ ingredient {} ({})",
            ingredient.title.as_deref().unwrap_or("untitled"),
            ingredient.relationship.as_deref().unwrap_or("unknown")
        );
    }
    for warning in &report.validation.warnings {
        println!("├─ warning      {}", warning.code);
    }
    for error in &report.validation.errors {
        println!("├─ error        {}", error.code);
    }
    println!(
        "└─ asset        {} · {} bytes · {}",
        report.asset.mime_type, report.asset.size_bytes, report.asset.sha256
    );
}

pub fn completions(shell: clap_complete::Shell) {
    use clap::CommandFactory;

    clap_complete::generate(
        shell,
        &mut crate::Cli::command(),
        "c2pa-check",
        &mut std::io::stdout(),
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Metric;
    use c2pa_check_core::report::{Asset, Credential, EngineInfo};

    fn report(status: CredentialStatus) -> Report {
        let mut report = Report::absent(
            EngineInfo {
                name: "c2pa-check-core".into(),
                version: "0".into(),
                trust_list_version: "2026-09-09-abc".into(),
            },
            Asset {
                sha256: "ab".into(),
                mime_type: "image/jpeg".into(),
                size_bytes: 1,
                width: None,
                height: None,
                pdq: None,
                pdq_quality: None,
                ..Asset::default()
            },
        );
        report.credential = Credential {
            present: !matches!(status, CredentialStatus::Absent),
            valid: matches!(
                status,
                CredentialStatus::ValidTrusted | CredentialStatus::ValidUntrusted
            ),
            trusted: status == CredentialStatus::ValidTrusted,
            status,
        };

        report
    }

    fn results(statuses: &[CredentialStatus]) -> Vec<(String, Option<Report>)> {
        statuses
            .iter()
            .enumerate()
            .map(|(index, status)| (format!("f{index}.jpg"), Some(report(*status))))
            .collect()
    }

    fn rendered(f: impl FnOnce(&mut Vec<u8>) -> anyhow::Result<()>) -> String {
        let mut buffer = Vec::new();
        f(&mut buffer).expect("a writable buffer");

        String::from_utf8(buffer).expect("utf-8 output")
    }

    #[test]
    fn every_status_has_its_own_colour() {
        let mut seen = Vec::new();
        for status in [
            CredentialStatus::Absent,
            CredentialStatus::PresentInvalid,
            CredentialStatus::ValidUntrusted,
            CredentialStatus::ValidTrusted,
        ] {
            let colour = tint(status);

            assert!(!seen.contains(&colour), "{status:?} reuses a colour");
            seen.push(colour);
        }
    }

    #[test]
    fn colour_is_left_out_when_the_output_is_not_a_terminal() {
        let plain = rendered(|out| {
            text(
                out,
                "a.jpg",
                Some(&report(CredentialStatus::ValidTrusted)),
                false,
            )
        });
        let tinted = rendered(|out| {
            text(
                out,
                "a.jpg",
                Some(&report(CredentialStatus::ValidTrusted)),
                true,
            )
        });

        assert!(!plain.contains('\x1b'));
        assert!(tinted.contains('\x1b'));
    }

    #[test]
    fn an_unreadable_target_says_so_instead_of_claiming_absence() {
        let out = rendered(|out| text(out, "broken.jpg", None, false));

        assert!(out.contains("COULD NOT BE READ"));
        assert!(!out.contains("ABSENT"));
    }

    #[test]
    fn an_absent_credential_is_never_reported_as_a_verdict_on_the_file() {
        let out =
            rendered(|out| text(out, "a.jpg", Some(&report(CredentialStatus::Absent)), false));

        assert!(out.contains("ABSENT"));
        assert!(!out.to_lowercase().contains("fake"));
        assert!(!out.to_lowercase().contains("real"));
        assert!(!out.contains("Manifest"));
    }

    #[test]
    fn an_untrusted_signer_is_reported_as_valid_but_unlisted() {
        let out = rendered(|out| {
            text(
                out,
                "a.jpg",
                Some(&report(CredentialStatus::ValidUntrusted)),
                false,
            )
        });

        assert!(out.contains("VALID"));
        assert!(out.contains("NOT ON THE TRUST LIST"));
    }

    #[test]
    fn a_traced_file_names_the_origin_signer_and_is_never_called_trusted() {
        let mut carried = report(CredentialStatus::ValidUntrusted);
        carried.origin = c2pa_check_core::Origin {
            status: c2pa_check_core::OriginStatus::Traced,
            signer_name: Some("OpenAI".into()),
            relationship: Some("parentOf".into()),
            depth: Some(1),
        };

        let out = rendered(|out| text(out, "a.webp", Some(&carried), false));

        assert!(out.contains("Origin                TRACED to OpenAI, 1 ingredient step(s) back"));
        assert!(out.contains("NOT ON THE TRUST LIST"));
        assert!(!out.contains("TRUSTED ("));
    }

    #[test]
    fn coverage_is_the_share_of_trusted_files() {
        assert_eq!(
            coverage(&results(&[CredentialStatus::ValidTrusted]), &[]),
            100.0
        );
        assert_eq!(
            coverage(
                &results(&[CredentialStatus::ValidTrusted, CredentialStatus::Absent]),
                &[]
            ),
            50.0
        );
    }

    #[test]
    fn coverage_of_nothing_is_zero_rather_than_a_division_by_zero() {
        assert_eq!(coverage(&[], &[]), 0.0);
        assert!(coverage(&[], &[]).is_finite());
    }

    fn gates(metric: Metric, expected: &[bool]) -> Vec<Gate> {
        expected
            .iter()
            .map(|expected| Gate {
                metric,
                expected: *expected,
            })
            .collect()
    }

    fn carried_and_drawn() -> Vec<(String, Option<Report>)> {
        let mut set = results(&[
            CredentialStatus::ValidUntrusted,
            CredentialStatus::ValidUntrusted,
            CredentialStatus::Absent,
        ]);
        set[0].1.as_mut().unwrap().origin.status = c2pa_check_core::OriginStatus::Traced;

        set
    }

    #[test]
    fn every_report_names_the_metric_beside_the_share_and_leaves_unexpected_files_out() {
        let set = carried_and_drawn();
        let traced = gates(Metric::Traced, &[true, true, false]);

        let text = rendered(|out| summary(out, &set, &traced));
        let xml = rendered(|out| junit(out, &set, &traced));
        let json = rendered(|out| render(Format::Json, &set, &traced, false, out));
        let ndjson = rendered(|out| render(Format::Ndjson, &set, &traced, false, out));
        let default = rendered(|out| summary(out, &set, &[]));
        let mixed = rendered(|out| {
            let mut two = traced.clone();
            two[1].metric = Metric::Valid;
            summary(out, &set, &two)
        });

        assert!(text.contains("coverage 50.0% traced"), "{text}");
        assert!(!text.contains("missing: f2.jpg"), "{text}");
        assert!(default.contains("coverage 0.0% trusted"), "{default}");
        assert!(default.contains("missing: f2.jpg"));
        assert!(mixed.contains("coverage 100.0% mixed"), "{mixed}");
        assert!(xml.contains(r#"<property name="coverage_metric" value="traced"/>"#));
        assert!(xml.contains(r#"<property name="coverage" value="50.0"/>"#));
        assert!(xml.contains(r#"tests="3" failures="1""#), "{xml}");
        assert!(xml.contains("origin.status is none; not traced"), "{xml}");
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(
            parsed[0]["coverage"],
            serde_json::json!({"metric": "traced", "expected": true, "covered": true})
        );
        assert_eq!(parsed[1]["coverage"]["covered"], false);
        assert_eq!(
            parsed[2]["coverage"],
            serde_json::json!({"metric": "traced", "expected": false, "covered": false})
        );
        assert_eq!(ndjson.lines().count(), 3);
        assert!(ndjson
            .lines()
            .all(|line| line.contains(r#""metric":"traced""#)));
    }

    #[test]
    fn the_summary_lists_missing_files_up_to_a_cap() {
        let many = results(&[CredentialStatus::Absent; MAX_LISTED_MISSING + 5]);

        let out = rendered(|out| summary(out, &many, &[]));

        assert_eq!(out.matches("  missing: ").count(), MAX_LISTED_MISSING);
        assert!(out.contains("… and 5 more"));
    }

    #[test]
    fn junit_counts_anything_but_trusted_as_a_failure() {
        let set = results(&[
            CredentialStatus::ValidTrusted,
            CredentialStatus::ValidUntrusted,
            CredentialStatus::Absent,
        ]);

        let out = rendered(|out| junit(out, &set, &[]));

        assert!(out.contains(r#"tests="3" failures="2""#));
        assert!(out.contains(r#"<property name="coverage_metric" value="trusted"/>"#));
        assert_eq!(out.matches("<failure").count(), 2);
    }

    #[test]
    fn junit_reports_an_unreadable_target_as_an_error_not_a_failure() {
        let set = vec![("broken.jpg".to_string(), None)];

        let out = rendered(|out| junit(out, &set, &[]));

        assert!(out.contains("<error message=\"unreadable\"/>"));
        assert!(!out.contains("<failure"));
    }

    #[test]
    fn junit_escapes_a_name_that_would_otherwise_break_the_document() {
        let set = vec![(r#"a&b<c>"d".jpg"#.to_string(), None)];

        let out = rendered(|out| junit(out, &set, &[]));

        assert!(out.contains("a&amp;b&lt;c&gt;&quot;d&quot;.jpg"));
        assert!(!out.contains("<c>"));
    }

    #[test]
    fn escaping_replaces_control_characters_that_no_xml_parser_accepts() {
        assert_eq!(escape("a\u{0}b"), "a?b");
        assert_eq!(escape("a\tb"), "a b");
        assert_eq!(escape("plain.jpg"), "plain.jpg");
    }

    #[test]
    fn json_carries_the_target_beside_every_result() {
        let set = results(&[CredentialStatus::ValidTrusted]);

        let out = rendered(|out| render(Format::Json, &set, &[], false, out));

        let parsed: serde_json::Value = serde_json::from_str(&out).expect("json output");
        assert_eq!(parsed[0]["target"], "f0.jpg");
        assert_eq!(parsed[0]["result"]["credential"]["status"], "valid_trusted");
    }
}

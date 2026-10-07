use std::io::Write;

use c2pa_check_core::{CredentialStatus, Report, SourceCategory};

use crate::Format;

pub fn render(
    format: Format,
    results: &[(String, Option<Report>)],
    color: bool,
) -> anyhow::Result<()> {
    let mut out = std::io::stdout().lock();

    match format {
        Format::Text => {
            for (target, report) in results {
                text(&mut out, target, report.as_ref(), color)?;
            }
            if results.len() > 1 {
                summary(&mut out, results)?;
            }
        }
        Format::Json => {
            let documents: Vec<_> = results
                .iter()
                .map(|(target, report)| serde_json::json!({ "target": target, "result": report }))
                .collect();
            serde_json::to_writer_pretty(&mut out, &documents)?;
            writeln!(out)?;
        }
        Format::Ndjson => {
            for (target, report) in results {
                serde_json::to_writer(
                    &mut out,
                    &serde_json::json!({ "target": target, "result": report }),
                )?;
                writeln!(out)?;
            }
        }
        Format::Junit => junit(&mut out, results)?,
    }

    Ok(())
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

fn coverage(results: &[(String, Option<Report>)]) -> f64 {
    if results.is_empty() {
        return 0.0;
    }

    let trusted = results
        .iter()
        .filter(|(_, report)| {
            report
                .as_ref()
                .is_some_and(|r| r.credential.status == CredentialStatus::ValidTrusted)
        })
        .count();

    trusted as f64 / results.len() as f64 * 100.0
}

fn summary(out: &mut impl Write, results: &[(String, Option<Report>)]) -> anyhow::Result<()> {
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
        .filter(|(_, r)| {
            r.as_ref()
                .is_some_and(|r| r.credential.status == CredentialStatus::Absent)
        })
        .map(|(target, _)| target.as_str())
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
        "coverage {:.1}%   monitor production provenance at https://c2pa.design",
        coverage(results)
    )?;

    Ok(())
}

fn junit(out: &mut impl Write, results: &[(String, Option<Report>)]) -> anyhow::Result<()> {
    let failures = results
        .iter()
        .filter(|(_, r)| {
            r.as_ref()
                .is_none_or(|r| r.credential.status != CredentialStatus::ValidTrusted)
        })
        .count();

    writeln!(out, r#"<?xml version="1.0" encoding="UTF-8"?>"#)?;
    writeln!(
        out,
        r#"<testsuite name="c2pa-check" tests="{}" failures="{}">"#,
        results.len(),
        failures
    )?;
    for (target, report) in results {
        let name = escape(target);
        match report {
            Some(r) if r.credential.status == CredentialStatus::ValidTrusted => {
                writeln!(out, r#"  <testcase name="{name}"/>"#)?;
            }
            Some(r) => {
                writeln!(out, r#"  <testcase name="{name}">"#)?;
                writeln!(
                    out,
                    r#"    <failure message="{}">credential.status is {}</failure>"#,
                    escape(r.credential.status.as_str()),
                    escape(r.credential.status.as_str())
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
    fn coverage_is_the_share_of_trusted_files() {
        assert_eq!(coverage(&results(&[CredentialStatus::ValidTrusted])), 100.0);
        assert_eq!(
            coverage(&results(&[
                CredentialStatus::ValidTrusted,
                CredentialStatus::Absent
            ])),
            50.0
        );
    }

    #[test]
    fn coverage_of_nothing_is_zero_rather_than_a_division_by_zero() {
        assert_eq!(coverage(&[]), 0.0);
        assert!(coverage(&[]).is_finite());
    }

    #[test]
    fn the_summary_lists_missing_files_up_to_a_cap() {
        let many = results(&[CredentialStatus::Absent; MAX_LISTED_MISSING + 5]);

        let out = rendered(|out| summary(out, &many));

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

        let out = rendered(|out| junit(out, &set));

        assert!(out.contains(r#"tests="3" failures="2""#));
        assert_eq!(out.matches("<failure").count(), 2);
    }

    #[test]
    fn junit_reports_an_unreadable_target_as_an_error_not_a_failure() {
        let set = vec![("broken.jpg".to_string(), None)];

        let out = rendered(|out| junit(out, &set));

        assert!(out.contains("<error message=\"unreadable\"/>"));
        assert!(!out.contains("<failure"));
    }

    #[test]
    fn junit_escapes_a_name_that_would_otherwise_break_the_document() {
        let set = vec![(r#"a&b<c>"d".jpg"#.to_string(), None)];

        let out = rendered(|out| junit(out, &set));

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

        let out = rendered(|out| {
            let documents: Vec<_> = set
                .iter()
                .map(|(target, report)| serde_json::json!({ "target": target, "result": report }))
                .collect();
            serde_json::to_writer(out, &documents)?;

            Ok(())
        });

        let parsed: serde_json::Value = serde_json::from_str(&out).expect("json output");
        assert_eq!(parsed[0]["target"], "f0.jpg");
        assert_eq!(parsed[0]["result"]["credential"]["status"], "valid_trusted");
    }
}

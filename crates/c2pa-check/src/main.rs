mod api;
mod apply;
mod baseline;
mod carry_cmd;
mod config;
mod doctor;
mod env;
mod fetch;
mod login;
mod mcp;
mod output;
mod register;
mod telemetry;
#[cfg(test)]
mod test_server;
mod trust_cmd;

use std::io::IsTerminal;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use c2pa_check_core::{report::TrustSelector, Options, Report, TrustBundle, Verifier};
use clap::{Parser, Subcommand, ValueEnum};

const EXIT_EXPECTATION: u8 = 1;
const EXIT_USAGE: u8 = 2;
const EXIT_PARSE: u8 = 3;
const EXIT_NETWORK: u8 = 4;
const EXIT_CRASH: u8 = 101;

#[derive(Parser)]
#[command(
    name = "c2pa-check",
    version,
    about = "Verify Content Credentials in files and URLs.",
    long_about = "Verify Content Credentials in files and URLs, and fail a build when \
provenance disappears. Monitor production provenance at https://c2pa.design."
)]
struct Cli {
    #[arg(value_name = "TARGET")]
    targets: Vec<String>,

    #[arg(long, value_enum, default_value_t = TrustArg::Official)]
    trust: TrustArg,

    #[arg(long, value_name = "PATH")]
    trust_anchors: Option<PathBuf>,

    #[arg(
        long,
        value_enum,
        help = "report format, text by default; repeat with --output for several reports from one run"
    )]
    format: Vec<Format>,

    #[arg(
        long,
        value_name = "PATH",
        help = "write the report to PATH instead of stdout; the Nth --output takes the Nth --format \
(--format json --output a.json --format junit --output a.xml)"
    )]
    output: Vec<PathBuf>,

    #[arg(long, value_enum)]
    expect: Option<Expect>,

    #[arg(long, value_name = "PCT")]
    coverage: Option<f64>,

    #[arg(
        long,
        value_name = "PATH",
        help = "fail when a file that had a valid credential in this baseline has lost it"
    )]
    baseline: Option<PathBuf>,

    #[arg(
        long,
        help = "write the baseline (--baseline, or each check's in c2pa.json) instead of comparing"
    )]
    update_baseline: bool,

    #[arg(
        long,
        help = "only check files git tracks, so local and CI runs count the same set"
    )]
    git_tracked: bool,

    #[arg(
        long,
        help = "after the check, register the files with c2pa.design (POST /assets/sync, then /assets for new hashes); needs C2PA_API_KEY"
    )]
    register: bool,

    #[arg(
        long,
        global = true,
        value_name = "PATH",
        help = "settings file; ./c2pa.json is read when present and no TARGET is given"
    )]
    config: Option<PathBuf>,

    #[arg(long)]
    raw: bool,

    #[arg(long)]
    offline: bool,

    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    Inspect {
        target: String,
        #[arg(long)]
        json: bool,
    },
    Trust {
        #[command(subcommand)]
        action: trust_cmd::Action,
    },
    Completions {
        shell: clap_complete::Shell,
    },
    Mcp,
    #[command(
        about = "Check the API key, quota, network, webhook secret and Node version",
        long_about = "Check the setup c2pa-check and the c2pa.design API rely on: C2PA_API_KEY \
(deprecated fallback C2PA_DESIGN_API_KEY) format, key type, plan and remaining quota from GET /whoami, \
reachability of C2PA_API_BASE (fallback C2PA_DESIGN_API_URL, default https://api.c2pa.design/v1), the C2PA_WEBHOOK_SECRET \
format, and the Node.js version when run through npx.\n\nExit codes: 0 every check passed \
(warnings allowed), 1 a check failed."
    )]
    Doctor(doctor::DoctorArgs),
    #[command(
        about = "Carry a Content Credential from a signed original into a converted copy",
        long_about = "Carry a Content Credential from a signed original into a converted copy \
(resized, re-encoded, compressed). The copy gets a new manifest with the original as its \
parentOf ingredient and c2pa.transcoded / c2pa.resized actions, so the chain back to the \
generator survives the conversion.\n\nSigner, in order: C2PA_SIGN_CERT + C2PA_SIGN_KEY (your \
certificate, or *_FILE paths); C2PA_API_KEY (or the deprecated C2PA_DESIGN_API_KEY; signs as your organization via \
c2pa.design, falls back to a local key if unavailable); otherwise a local key kept in \
~/.config/c2pa-check/identity.\n\nComposites: --compose A B ... --to OUTPUT signs OUTPUT as a \
new work (c2pa.created, or c2pa.edited with --edited) with every source attached as a \
componentOf ingredient. With C2PA_API_KEY and a verified domain c2pa.design signs it when \
every component credential validates and at least one source has one; otherwise it is signed \
with the local key and a warning.\n\nExit codes: 0 carried and verified, 1 \
--strict and a file has no or an ambiguous original, 2 usage or I/O error, 5 refused (rule in \
--json: different_picture, source_unsigned, low_quality, not_comparable, or the rule \
c2pa.design returned with carry_rejected)."
    )]
    Carry(carry_cmd::CarryArgs),
    #[command(
        about = "Register files with c2pa.design: check, sync hashes, send only the new ones",
        long_about = "Check the files, ask c2pa.design which sha256 hashes it does not know \
(POST /assets/sync, 5000 per call) and register only those (POST /assets, 500 per call) with \
the file path as location. Bytes never leave the machine. Without TARGET the paths of every \
check in c2pa.json are used. Retries follow error.retryable and Retry-After, five attempts.\n\n\
Exit codes: 0 registered, 2 usage, 3 a file could not be read, 4 the API call failed."
    )]
    Register {
        #[arg(value_name = "TARGET")]
        targets: Vec<String>,
        #[arg(long, help = "only files git tracks")]
        git_tracked: bool,
    },
    #[command(
        about = "Make the account match c2pa.json: webhooks, monitors, domains",
        long_about = "Create or update what c2pa.json declares; safe to run on every deploy. \
Webhooks are matched by URL (PUT /webhooks), monitors by name, domains by host. Nothing is \
deleted. The webhook secret comes from C2PA_WEBHOOK_SECRET or the --secret-out file and is \
never printed; a changed secret is rotated in with a 24-hour overlap.\n\n\
Exit codes: 0 applied, 1 --wait ended with a domain still pending, 2 usage or API error."
    )]
    Apply(apply::ApplyArgs),
    #[command(
        about = "Sign in from a terminal: approve a code in the browser, get an API key",
        long_about = "Prints a link and a short code. Open the link on any device, sign in to \
c2pa.design and approve the code; a new API key is then saved in \
~/.config/c2pa-check/credentials (owner-only) and used whenever C2PA_API_KEY is not set. The key \
is never printed. --ci github|gitlab also stores it as the C2PA_API_KEY secret of the current \
repository through the gh or glab CLI.\n\nFor a person at a terminal only: a Docker build or a \
CI job cannot approve a code and takes the key from its secret store.\n\n\
Exit codes: 0 signed in, 1 the code was not approved in time, 2 usage or API error."
    )]
    Login(login::LoginArgs),
    #[command(hide = true, name = telemetry::SEND_COMMAND)]
    ReportSend {
        body: String,
    },
    #[command(
        about = "Write a certificate chain and private key for C2PA_SIGN_CERT / C2PA_SIGN_KEY"
    )]
    Keygen(carry_cmd::KeygenArgs),
}

#[derive(Copy, Clone, ValueEnum)]
enum TrustArg {
    Official,
    Interim,
    Both,
    None,
}

impl From<TrustArg> for TrustSelector {
    fn from(value: TrustArg) -> Self {
        match value {
            TrustArg::Official => Self::Official,
            TrustArg::Interim => Self::Interim,
            TrustArg::Both => Self::Both,
            TrustArg::None => Self::None,
        }
    }
}

#[derive(Copy, Clone, Default, ValueEnum)]
enum Format {
    #[default]
    Text,
    Json,
    Ndjson,
    Junit,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, ValueEnum, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Expect {
    Present,
    Trusted,
    Absent,
}

fn command_name(command: Option<&Command>) -> &'static str {
    match command {
        None => "check",
        Some(Command::Inspect { .. }) => "inspect",
        Some(Command::Trust { .. }) => "trust",
        Some(Command::Completions { .. }) => "completions",
        Some(Command::Mcp) => "mcp",
        Some(Command::Doctor(_)) => "doctor",
        Some(Command::Carry(_)) => "carry",
        Some(Command::Keygen(_)) => "keygen",
        Some(Command::Register { .. }) => "register",
        Some(Command::Apply(_)) => "apply",
        Some(Command::Login(_)) => "login",
        Some(Command::ReportSend { .. }) => telemetry::SEND_COMMAND,
    }
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let (command, offline) = (command_name(cli.command.as_ref()), cli.offline);
    telemetry::panic_hook();

    let code = match std::panic::catch_unwind(|| run(cli)) {
        Ok(Ok(code)) => code,
        Ok(Err(err)) => {
            eprintln!("c2pa-check: {err}");
            if let Some(api) = err.downcast_ref::<api::ApiError>() {
                telemetry::note(&format!("api.{}.{}", api.status, api.code));
            }

            EXIT_USAGE
        }
        Err(_) => EXIT_CRASH,
    };
    let silent = matches!(code, 0 | EXIT_EXPECTATION)
        || matches!(command, "doctor" | "mcp" | telemetry::SEND_COMMAND);
    if !silent {
        telemetry::report(command, code, offline);
    }

    ExitCode::from(code)
}

fn run(mut cli: Cli) -> anyhow::Result<u8> {
    match cli.command.take() {
        Some(Command::Completions { shell }) => {
            output::completions(shell);

            return Ok(0);
        }
        Some(Command::Trust { action }) => return trust_cmd::run(action, cli.offline),
        Some(Command::Mcp) => return mcp::serve(load_bundle(&cli)?),
        Some(Command::Inspect { target, json }) => return inspect(&cli, &target, json),
        Some(Command::Keygen(args)) => return carry_cmd::keygen(args),
        Some(Command::Doctor(args)) => return doctor::run(&args),
        Some(Command::Carry(args)) => {
            let bundle = load_bundle(&cli)?;
            let verifier = verifier_for(&bundle, cli.trust.into())?;

            return carry_cmd::run(args, &verifier);
        }
        Some(Command::Login(args)) => return login::run(&args),
        Some(Command::ReportSend { body }) => {
            telemetry::send(&body);

            return Ok(0);
        }
        Some(Command::Apply(args)) => {
            if skipped_without_key(env::api_key().as_deref(), "apply") {
                return Ok(0);
            }

            return apply::run(&args, &config::require(cli.config.as_deref())?);
        }
        Some(Command::Register {
            targets,
            git_tracked,
        }) => {
            if skipped_without_key(env::api_key().as_deref(), "register") {
                return Ok(0);
            }
            cli.targets = targets;
            cli.git_tracked |= git_tracked;
            let mut sets = sets(&cli)?;
            for set in &mut sets {
                set.expect = None;
                set.coverage = None;
                set.baseline = None;
            }
            let checked = check(&cli, &sets)?;
            let registered = register(&checked.results)?;

            return Ok(checked.read_failure().unwrap_or(registered));
        }
        None => {}
    }

    let reports = reports(&cli.format, &cli.output)?;
    let sets = sets(&cli)?;
    let checked = check(&cli, &sets)?;

    for (format, path) in reports {
        write_report(format, &checked.results, path)?;
    }
    for failure in &checked.failures {
        eprintln!("c2pa-check: {failure}");
    }
    let registered = if cli.register {
        register(&checked.results)?
    } else {
        0
    };

    if let Some(code) = checked.read_failure() {
        return Ok(code);
    }
    if !checked.failures.is_empty() {
        return Ok(EXIT_EXPECTATION);
    }

    Ok(registered)
}

struct Set {
    name: String,
    targets: Vec<String>,
    expect: Option<Expect>,
    coverage: Option<f64>,
    baseline: Option<PathBuf>,
    git_tracked: bool,
}

struct Checked {
    results: Vec<(String, Option<Report>)>,
    failures: Vec<String>,
    network_failure: bool,
    parse_failure: bool,
}

impl Checked {
    fn read_failure(&self) -> Option<u8> {
        if self.network_failure {
            return Some(EXIT_NETWORK);
        }

        self.parse_failure.then_some(EXIT_PARSE)
    }
}

fn sets(cli: &Cli) -> anyhow::Result<Vec<Set>> {
    if !cli.targets.is_empty() {
        return Ok(vec![Set {
            name: String::new(),
            targets: cli.targets.clone(),
            expect: cli.expect,
            coverage: cli.coverage,
            baseline: cli.baseline.clone(),
            git_tracked: cli.git_tracked,
        }]);
    }

    let checks = config::load(cli.config.as_deref())?
        .map(|c| c.checks)
        .unwrap_or_default();
    if checks.is_empty() {
        anyhow::bail!(
            "give at least one file, glob or URL, or list checks in {} (--help for usage)",
            config::DEFAULT_PATH
        );
    }

    Ok(checks
        .into_iter()
        .map(|c| Set {
            name: c.name,
            targets: c.paths,
            expect: c.expect,
            coverage: c.coverage,
            baseline: c.baseline,
            git_tracked: c.git_tracked || cli.git_tracked,
        })
        .collect())
}

fn reports<'a>(
    formats: &[Format],
    outputs: &'a [PathBuf],
) -> anyhow::Result<Vec<(Format, Option<&'a Path>)>> {
    match (formats.len(), outputs.len()) {
        (_, 0) | (0, 1) => Ok(vec![(
            formats.last().copied().unwrap_or_default(),
            outputs.first().map(PathBuf::as_path),
        )]),
        (f, o) if f == o => Ok(formats
            .iter()
            .copied()
            .zip(outputs.iter().map(|p| Some(p.as_path())))
            .collect()),
        (f, o) => anyhow::bail!("{f} --format and {o} --output: give one --format per --output"),
    }
}

fn tracked() -> anyhow::Result<std::collections::HashSet<String>> {
    let listed = std::process::Command::new("git")
        .args(["ls-files", "-z"])
        .output()
        .map_err(|err| anyhow::anyhow!("--git-tracked could not run git: {err}"))?;
    if !listed.status.success() {
        anyhow::bail!(
            "--git-tracked needs a git work tree: {}",
            String::from_utf8_lossy(&listed.stderr).trim()
        );
    }

    Ok(listed
        .stdout
        .split(|b| *b == 0)
        .map(|path| String::from_utf8_lossy(path).to_string())
        .collect())
}

fn check(cli: &Cli, sets: &[Set]) -> anyhow::Result<Checked> {
    let bundle = load_bundle(cli)?;
    let verifier = verifier_for(&bundle, cli.trust.into())?;
    let options = Options {
        include_raw: cli.raw,
        ..Options::default()
    };
    let tracked = if sets.iter().any(|s| s.git_tracked) {
        tracked()?
    } else {
        Default::default()
    };

    let mut checked = Checked {
        results: Vec::new(),
        failures: Vec::new(),
        network_failure: false,
        parse_failure: false,
    };

    for set in sets {
        let mut targets = expand(&set.targets)?;
        if set.git_tracked {
            targets.retain(|t| is_url(t) || tracked.contains(t.trim_start_matches("./")));
            if targets.is_empty() {
                anyhow::bail!("{}: no file git tracks matched", set.targets.join(" "));
            }
        }

        let first = checked.results.len();
        for target in &targets {
            match load(target, cli.offline) {
                Ok((bytes, mime)) => match verifier.verify(&bytes, &mime, &options) {
                    Ok(report) => checked.results.push((target.clone(), Some(report))),
                    Err(err) => {
                        eprintln!("{target}: {err}");
                        telemetry::note(err.code());
                        telemetry::note_mime(&mime);
                        checked.parse_failure = true;
                        checked.results.push((target.clone(), None));
                    }
                },
                Err(err) => {
                    eprintln!("{target}: {err:#}");
                    if failure_exit(target) == EXIT_NETWORK {
                        checked.network_failure = true;
                    } else {
                        checked.parse_failure = true;
                    }
                    checked.results.push((target.clone(), None));
                }
            }
        }

        let results = &checked.results[first..];
        let label = if set.name.is_empty() {
            String::new()
        } else {
            format!("{}: ", set.name)
        };
        let mut failures: Vec<String> = judge(results, set.expect, set.coverage)
            .into_iter()
            .map(|failure| format!("{label}{failure}"))
            .collect();
        if let Some(path) = &set.baseline {
            if cli.update_baseline {
                baseline::write(path, &baseline::snapshot(results))?;
            } else {
                failures.extend(
                    baseline::regressions(&baseline::load(path)?, results)
                        .into_iter()
                        .map(|lost| format!("{label}credential lost since the baseline: {lost}")),
                );
            }
        }
        checked.failures.extend(failures);
    }

    Ok(checked)
}

fn skipped_without_key(key: Option<&str>, step: &str) -> bool {
    if key.is_some() {
        return false;
    }
    eprintln!(
        "c2pa-check: warning: C2PA_API_KEY is not set; skipped {step}, nothing was sent. \
Run `c2pa-check login` or create a key at https://app.c2pa.design."
    );

    true
}

fn register(results: &[(String, Option<Report>)]) -> anyhow::Result<u8> {
    if skipped_without_key(env::api_key().as_deref(), "register") {
        return Ok(0);
    }
    let api = api::Api::from_env()?;
    match register::run(&api, results) {
        Ok(done) => {
            eprintln!(
                "c2pa-check: {} distinct files, {} newly registered",
                done.total, done.new
            );

            Ok(0)
        }
        Err(err) => {
            eprintln!("c2pa-check: registering assets failed: {err}");
            telemetry::note(&format!("api.{}.{}", err.status, err.code));

            Ok(EXIT_NETWORK)
        }
    }
}

fn write_report(
    format: Format,
    results: &[(String, Option<Report>)],
    path: Option<&Path>,
) -> anyhow::Result<()> {
    let Some(path) = path else {
        return output::render(
            format,
            results,
            std::io::stdout().is_terminal(),
            &mut std::io::stdout().lock(),
        );
    };
    let file = std::fs::File::create(path)
        .map_err(|e| anyhow::anyhow!("writing {}: {e}", path.display()))?;
    let mut writer = std::io::BufWriter::new(file);
    output::render(format, results, false, &mut writer)?;
    std::io::Write::flush(&mut writer)
        .map_err(|e| anyhow::anyhow!("writing {}: {e}", path.display()))
}

fn inspect(cli: &Cli, target: &str, json: bool) -> anyhow::Result<u8> {
    let bundle = load_bundle(cli)?;
    let (bytes, mime) = load(target, cli.offline)?;
    let options = Options {
        include_raw: true,
        ..Options::default()
    };

    let report = verifier_for(&bundle, cli.trust.into())?.verify(&bytes, &mime, &options)?;
    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        output::tree(target, &report);
    }

    Ok(0)
}

fn verifier_for(bundle: &TrustBundle, trust: TrustSelector) -> anyhow::Result<Verifier> {
    Verifier::new(bundle, trust).map_err(|err| {
        anyhow::anyhow!(
            "the trust list {} could not be loaded ({err}); run `c2pa-check trust update`",
            bundle.version
        )
    })
}

fn load_bundle(cli: &Cli) -> anyhow::Result<TrustBundle> {
    if let Some(path) = &cli.trust_anchors {
        return Ok(TrustBundle::from_files(path, None, "custom")?);
    }
    if cli.offline {
        return Ok(TrustBundle::bundled());
    }

    trust_cmd::active()
}

fn failure_exit(target: &str) -> u8 {
    if is_url(target) {
        EXIT_NETWORK
    } else {
        EXIT_PARSE
    }
}

fn is_url(target: &str) -> bool {
    target.starts_with("http://") || target.starts_with("https://")
}

fn load(target: &str, offline: bool) -> anyhow::Result<(Vec<u8>, String)> {
    if is_url(target) {
        if offline {
            anyhow::bail!("--offline refuses to fetch {target}");
        }

        return fetch::get(target);
    }

    let bytes = carry_cmd::read_media(Path::new(target))?;
    let mime = c2pa_check_core::media::mime_from_extension(target).to_string();

    Ok((bytes, mime))
}

fn expand(targets: &[String]) -> anyhow::Result<Vec<String>> {
    let mut out = Vec::new();

    for target in targets {
        if is_url(target) || !target.contains(['*', '?', '[', '{']) {
            out.push(target.clone());

            continue;
        }

        let before = out.len();
        for pattern in braces(target) {
            for entry in glob::glob(&pattern)? {
                let path = entry?;
                if path.is_file() {
                    out.push(path.to_string_lossy().to_string());
                }
            }
        }
        if out.len() == before {
            anyhow::bail!("{target} matched no files");
        }
    }

    Ok(out)
}

fn braces(pattern: &str) -> Vec<String> {
    let Some(open) = pattern.find('{') else {
        return vec![pattern.to_string()];
    };
    let Some(len) = pattern[open..].find('}') else {
        return vec![pattern.to_string()];
    };
    let close = open + len;

    pattern[open + 1..close]
        .split(',')
        .flat_map(|alt| {
            braces(&format!(
                "{}{alt}{}",
                &pattern[..open],
                &pattern[close + 1..]
            ))
        })
        .collect()
}

fn judge(
    results: &[(String, Option<Report>)],
    expect: Option<Expect>,
    coverage: Option<f64>,
) -> Vec<String> {
    use c2pa_check_core::CredentialStatus as S;

    let mut failures = Vec::new();

    if let Some(expect) = expect {
        let (want, word): (&[S], _) = match expect {
            Expect::Present => (&[S::ValidTrusted, S::ValidUntrusted], "present"),
            Expect::Trusted => (&[S::ValidTrusted], "trusted"),
            Expect::Absent => (&[S::Absent], "absent"),
        };
        let off = results
            .iter()
            .filter(|(_, report)| {
                !report
                    .as_ref()
                    .is_some_and(|r| want.contains(&r.credential.status))
            })
            .count();
        if off > 0 {
            failures.push(format!("{off} of {} are not {word}", results.len()));
        }
    }

    if let Some(threshold) = coverage {
        let total = results.len();
        let trusted = results
            .iter()
            .filter(|(_, report)| {
                report
                    .as_ref()
                    .is_some_and(|r| r.credential.status == S::ValidTrusted)
            })
            .count();
        let pct = if total == 0 {
            100.0
        } else {
            trusted as f64 / total as f64 * 100.0
        };
        if pct + f64::EPSILON < threshold {
            failures.push(format!(
                "coverage {pct:.1}% ({trusted} of {total} trusted) is below {threshold}"
            ));
        }
    }

    failures
}

#[cfg(test)]
mod tests {
    use super::*;
    use c2pa_check_core::report::{Asset, Credential, CredentialStatus, EngineInfo};

    fn report(status: CredentialStatus) -> Report {
        let mut r = Report::absent(
            EngineInfo {
                name: "t".into(),
                version: "0".into(),
                trust_list_version: "v".into(),
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
        r.credential = Credential {
            present: status != CredentialStatus::Absent,
            valid: matches!(
                status,
                CredentialStatus::ValidTrusted | CredentialStatus::ValidUntrusted
            ),
            trusted: status == CredentialStatus::ValidTrusted,
            status,
        };
        r
    }

    fn meets_expectations(
        results: &[(String, Option<Report>)],
        expect: Option<Expect>,
        coverage: Option<f64>,
    ) -> bool {
        judge(results, expect, coverage).is_empty()
    }

    #[test]
    fn targets_on_the_command_line_are_one_set_carrying_the_flags() {
        let cli = Cli::parse_from([
            "c2pa-check",
            "a.png",
            "b.png",
            "--coverage",
            "80",
            "--expect",
            "trusted",
            "--baseline",
            "base.json",
            "--git-tracked",
        ]);

        let got = sets(&cli).unwrap();

        assert_eq!(got.len(), 1);
        assert_eq!(got[0].targets, ["a.png", "b.png"]);
        assert_eq!(got[0].coverage, Some(80.0));
        assert_eq!(got[0].expect, Some(Expect::Trusted));
        assert_eq!(got[0].baseline.as_deref(), Some(Path::new("base.json")));
        assert!(got[0].git_tracked && got[0].name.is_empty());
    }

    #[test]
    fn checks_come_from_the_config_and_a_config_without_checks_is_a_usage_error() {
        let dir = std::env::temp_dir().join(format!("c2pa-check-sets-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let (full, empty) = (dir.join("full.json"), dir.join("empty.json"));
        std::fs::write(
            &full,
            r#"{"checks":[{"name":"shipped","paths":["public/*.webp"],"baseline":"b.json"},
                          {"name":"sources","paths":["design/*.png"],"coverage":39}]}"#,
        )
        .unwrap();
        std::fs::write(&empty, r#"{"domains":["example.com"]}"#).unwrap();
        let with =
            |path: &Path| Cli::parse_from(["c2pa-check", "--config", &path.to_string_lossy()]);

        let got = sets(&with(&full)).unwrap();
        let none = sets(&with(&empty));
        std::fs::remove_dir_all(&dir).ok();

        assert_eq!(got.len(), 2);
        assert_eq!((got[0].name.as_str(), got[0].coverage), ("shipped", None));
        assert_eq!(
            (got[1].name.as_str(), got[1].coverage),
            ("sources", Some(39.0))
        );
        assert!(!got[1].git_tracked);
        assert!(none.is_err());
    }

    #[test]
    fn git_tracked_lists_committed_files_only() {
        let listed = tracked().unwrap();

        assert!(listed.contains("src/main.rs"));
        assert!(!listed.contains("src/never-committed.rs"));
    }

    #[test]
    fn a_set_is_judged_against_its_baseline_and_update_writes_it() {
        let dir = std::env::temp_dir().join(format!("c2pa-check-base-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("empty.png");
        std::fs::write(&file, b"not a picture").unwrap();
        let (target, base) = (file.to_string_lossy().to_string(), dir.join("base.json"));
        let run = |extra: &[&str]| {
            let mut args = vec!["c2pa-check", "--offline", target.as_str(), "--baseline"];
            let base = base.to_string_lossy().to_string();
            args.push(&base);
            args.extend(extra);
            let cli = Cli::parse_from(args);
            check(&cli, &sets(&cli).unwrap())
        };

        let missing = run(&[]);
        let written = run(&["--update-baseline"]).unwrap();
        let recorded = std::fs::read_to_string(&base).unwrap();
        std::fs::write(
            &base,
            recorded
                .replace("\"error\"", "\"valid_trusted\"")
                .replace("\"absent\"", "\"valid_trusted\""),
        )
        .unwrap();
        let compared = run(&[]).unwrap();
        std::fs::remove_dir_all(&dir).ok();

        assert!(missing.is_err());
        assert!(written.failures.is_empty());
        assert_eq!(compared.failures.len(), 1);
        assert!(compared.failures[0].contains("credential lost since the baseline"));
    }

    pub fn results_named(named: &[(&str, CredentialStatus)]) -> Vec<(String, Option<Report>)> {
        named
            .iter()
            .map(|(name, status)| (name.to_string(), Some(report(*status))))
            .collect()
    }

    #[test]
    fn a_missing_key_skips_the_step_instead_of_failing() {
        assert!(skipped_without_key(None, "register"));
        assert!(!skipped_without_key(Some("c2pa_test_x"), "register"));
    }

    #[test]
    fn formats_pair_with_outputs_by_position() {
        let (a, b) = (PathBuf::from("a.json"), PathBuf::from("b.xml"));
        let outputs = [a.clone(), b.clone()];

        let pairs = reports(&[Format::Json, Format::Junit], &outputs).unwrap();
        let stdout = reports(&[Format::Ndjson], &[]).unwrap();
        let default = reports(&[], &outputs[..1]).unwrap();

        assert!(matches!(pairs[0], (Format::Json, Some(p)) if p == a));
        assert!(matches!(pairs[1], (Format::Junit, Some(p)) if p == b));
        assert!(matches!(stdout[0], (Format::Ndjson, None)));
        assert!(matches!(default[0], (Format::Text, Some(_))));
        assert!(reports(&[Format::Json], &outputs).is_err());
    }

    #[test]
    fn a_failed_gate_says_which_number_missed() {
        let set = results(&[CredentialStatus::ValidTrusted, CredentialStatus::Absent]);

        let got = judge(&set, Some(Expect::Trusted), Some(80.0));

        assert_eq!(
            got,
            [
                "1 of 2 are not trusted",
                "coverage 50.0% (1 of 2 trusted) is below 80"
            ]
        );
    }

    fn results(statuses: &[CredentialStatus]) -> Vec<(String, Option<Report>)> {
        statuses
            .iter()
            .enumerate()
            .map(|(i, s)| (format!("f{i}.jpg"), Some(report(*s))))
            .collect()
    }

    #[test]
    fn braces_expand_every_alternative() {
        assert_eq!(
            braces("dist/**/*.{jpg,png}"),
            ["dist/**/*.jpg", "dist/**/*.png"]
        );
        assert_eq!(
            braces("{a,b}/x.{c,d}"),
            ["a/x.c", "a/x.d", "b/x.c", "b/x.d"]
        );
        assert_eq!(braces("plain/*.jpg"), ["plain/*.jpg"]);
        assert_eq!(braces("open{a,b"), ["open{a,b"]);
    }

    #[test]
    fn expand_matches_brace_globs_and_skips_directories() {
        let dir = std::env::temp_dir().join(format!("c2pa-check-expand-{}", std::process::id()));
        std::fs::create_dir_all(dir.join("nested.jpg")).unwrap();
        for name in ["a.jpg", "b.png", "c.txt"] {
            std::fs::write(dir.join(name), b"x").unwrap();
        }
        let root = dir.to_string_lossy();

        let mut got = expand(&[format!("{root}/*.{{jpg,png}}")]).unwrap();
        got.sort();
        let all = expand(&[format!("{root}/*")]).unwrap();
        let none = expand(&[format!("{root}/*.{{gif,avif}}")]);
        std::fs::remove_dir_all(&dir).unwrap();

        assert_eq!(got, [format!("{root}/a.jpg"), format!("{root}/b.png")]);
        assert_eq!(all.len(), 3);
        assert!(none.is_err());
    }

    #[test]
    fn expect_trusted_fails_on_an_untrusted_signer() {
        let set = results(&[
            CredentialStatus::ValidTrusted,
            CredentialStatus::ValidUntrusted,
        ]);

        assert!(!meets_expectations(&set, Some(Expect::Trusted), None));
        assert!(meets_expectations(&set, Some(Expect::Present), None));
    }

    #[test]
    fn coverage_is_the_share_of_trusted_assets() {
        let set = results(&[
            CredentialStatus::ValidTrusted,
            CredentialStatus::ValidTrusted,
            CredentialStatus::Absent,
        ]);

        assert!(meets_expectations(&set, None, Some(66.0)));
        assert!(!meets_expectations(&set, None, Some(100.0)));
    }

    #[test]
    fn a_url_is_never_treated_as_a_glob() {
        assert!(is_url("https://example.com/a.jpg"));
        assert!(is_url("http://example.com/a.jpg"));
        assert!(!is_url("http_report.jpg"));
        assert!(!is_url("./https/a.jpg"));
    }

    #[test]
    fn a_glob_that_matches_nothing_is_an_error_not_a_silent_pass() {
        let miss = expand(&["/nonexistent-directory-for-tests/*.jpg".to_string()]);

        assert!(miss.is_err());
    }

    #[test]
    fn a_plain_target_is_passed_through_untouched() {
        let out = expand(&[
            "photo.jpg".to_string(),
            "https://example.com/a.jpg".to_string(),
        ])
        .expect("no globs to expand");

        assert_eq!(out, vec!["photo.jpg", "https://example.com/a.jpg"]);
    }

    #[test]
    fn an_empty_result_set_never_satisfies_an_expectation_by_accident() {
        let empty: Vec<(String, Option<Report>)> = Vec::new();

        assert!(meets_expectations(&empty, Some(Expect::Trusted), None));
        assert!(meets_expectations(&empty, None, Some(100.0)));
    }

    #[test]
    fn a_target_that_could_not_be_read_never_counts_as_a_pass() {
        let set = vec![("broken.jpg".to_string(), None)];

        assert!(!meets_expectations(&set, Some(Expect::Absent), None));
    }

    #[test]
    fn output_writes_the_report_to_the_file() {
        let dir = std::env::temp_dir().join(format!("c2pa-check-output-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let json = dir.join("report.json");
        let junit = dir.join("report.xml");

        write_report(
            Format::Json,
            &results(&[CredentialStatus::Absent]),
            Some(&json),
        )
        .unwrap();
        write_report(
            Format::Junit,
            &results(&[CredentialStatus::Absent]),
            Some(&junit),
        )
        .unwrap();
        let written = std::fs::read_to_string(&json).unwrap();
        let xml = std::fs::read_to_string(&junit).unwrap();
        let missing = write_report(
            Format::Json,
            &results(&[CredentialStatus::Absent]),
            Some(&dir.join("no-such-dir").join("r.json")),
        );
        std::fs::remove_dir_all(&dir).ok();

        let value: serde_json::Value = serde_json::from_str(&written).unwrap();
        assert!(!value.is_null());
        assert!(written.contains("absent"));
        assert!(xml.starts_with("<?xml"), "{xml}");
        assert!(missing.unwrap_err().to_string().starts_with("writing "));
    }

    #[test]
    fn a_missing_local_file_is_unreadable_not_a_network_failure() {
        let err = load("/nonexistent/c2pa-check/missing.jpg", false).unwrap_err();

        assert!(format!("{err:#}").contains("missing.jpg"));
        assert_eq!(
            failure_exit("/nonexistent/c2pa-check/missing.jpg"),
            EXIT_PARSE
        );
        assert_eq!(failure_exit("https://example.com/a.jpg"), EXIT_NETWORK);
        assert_eq!(EXIT_PARSE, 3);
    }

    #[test]
    fn offline_refuses_a_url_as_a_network_failure() {
        let err = load("https://example.com/a.jpg", true).unwrap_err();

        assert!(err.to_string().contains("--offline"));
        assert_eq!(failure_exit("https://example.com/a.jpg"), 4);
    }
}

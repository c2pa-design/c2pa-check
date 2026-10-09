use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::Duration;

use anyhow::{anyhow, Context};
use base64::Engine as _;
use c2pa_check_core::carry::{
    self, CarryError, CarryOptions, CarryOutcome, DeferredSigner, LocalIdentity, PLACEHOLDER_LEN,
};
use c2pa_check_core::media::mime_from_extension;
use c2pa_check_core::report::CredentialStatus;
use c2pa_check_core::{Options, Verifier};
use clap::Args;
use serde::Serialize;
use serde_json::Value;

use crate::env;

pub const EXIT_REFUSED: u8 = 5;
pub const EXIT_UNPAIRED: u8 = 1;
pub const EXIT_ERROR: u8 = 2;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_WORKERS: usize = 8;
const MAX_COMPOSE_SOURCES: usize = 256;
const MAX_MEDIA_BYTES: u64 = 64 * 1024 * 1024;
const FALLBACK_CODES: [&str; 7] = [
    "usage_limit_exceeded",
    "rate_limited",
    "signing_disabled",
    "signing_unavailable",
    "unauthorized",
    "forbidden",
    "timeout",
];
const LOCAL_NAME: &str = "c2pa-check local identity";
const BOUNDARY_BYTES: usize = 12;
const SIGNER_HINT: &str = "set C2PA_API_KEY to sign as your organization, or C2PA_SIGN_CERT and C2PA_SIGN_KEY to sign with your own certificate";

#[derive(Args)]
pub struct CarryArgs {
    #[arg(long, value_name = "SOURCE", help = "the signed original")]
    from: Option<PathBuf>,
    #[arg(
        long,
        value_name = "DERIVED",
        help = "the converted file to carry the credential into"
    )]
    to: Option<PathBuf>,
    #[arg(
        long,
        value_name = "PATH",
        help = "write here instead of replacing --to"
    )]
    out: Option<PathBuf>,
    #[arg(
        long,
        value_name = "DIR",
        help = "folder of originals, paired with GLOB matches by file stem"
    )]
    from_dir: Option<PathBuf>,
    #[arg(
        value_name = "GLOB",
        help = "derived files to carry when --from-dir is given"
    )]
    paths: Vec<String>,
    #[arg(
        long,
        help = "carry media that cannot be compared as pictures (video, audio)"
    )]
    force: bool,
    #[arg(
        long,
        value_name = "SOURCE",
        num_args = 1..,
        conflicts_with_all = ["from", "from_dir"],
        help = "sign --to as a new work made from these files (each attached as a componentOf ingredient)"
    )]
    compose: Vec<PathBuf>,
    #[arg(
        long,
        requires = "compose",
        help = "with --compose: record c2pa.edited instead of c2pa.created"
    )]
    edited: bool,
    #[arg(long, help = "print one JSON document")]
    json: bool,
    #[arg(
        long,
        help = "exit 1 when a derived file has no or an ambiguous original"
    )]
    strict: bool,
}

#[derive(Args)]
pub struct KeygenArgs {
    #[arg(long, value_name = "DIR", default_value = ".")]
    out_dir: PathBuf,
    #[arg(long, value_name = "NAME", default_value = "c2pa-check signer")]
    name: String,
    #[arg(long, help = "also print the private key to stdout")]
    stdout: bool,
}

#[derive(Clone)]
enum Mode {
    Own { chain: String, key: String },
    Hosted { base: String, key: String },
    Local,
}

#[derive(Debug, Default, Serialize)]
struct Item {
    status: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    rule: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    message: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    source: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    sources: Vec<String>,
    #[serde(rename = "output", skip_serializing_if = "Option::is_none")]
    out: Option<String>,
    derived: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    signer_mode: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    signer: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    credential_status: Option<CredentialStatus>,
    #[serde(skip_serializing_if = "Option::is_none")]
    distance: Option<u32>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    actions: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    carry_id: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    warnings: Vec<String>,
}

struct Run<'a> {
    verifier: &'a Verifier,
    mode: Mode,
    tsa: Option<String>,
    force: bool,
    local: Mutex<Option<LocalIdentity>>,
    chain: Mutex<Option<Certificate>>,
    warnings: Vec<String>,
}

pub fn run(args: CarryArgs, verifier: &Verifier) -> anyhow::Result<u8> {
    let (mode, warnings) = mode_from_env();
    let context = Run {
        verifier,
        mode,
        tsa: env::value("C2PA_TSA_URL"),
        force: args.force,
        local: Mutex::new(None),
        chain: Mutex::new(None),
        warnings,
    };

    let items = match (&args.from, &args.to, &args.from_dir) {
        (None, Some(to), None) if !args.compose.is_empty() => {
            let out = args.out.clone().unwrap_or_else(|| to.clone());
            vec![compose_one(&context, &args.compose, to, &out, args.edited)]
        }
        (None, None, None) if !args.compose.is_empty() => {
            anyhow::bail!("--compose needs --to OUTPUT, the rendered composite to sign")
        }
        (Some(from), Some(to), None) => {
            let out = args.out.clone().unwrap_or_else(|| to.clone());
            vec![carry_one(&context, from, to, &out)]
        }
        (None, None, Some(dir)) if !args.paths.is_empty() => {
            if args.out.is_some() {
                anyhow::bail!("--out only applies to a single --from/--to pair");
            }
            batch(&context, dir, &args.paths)?
        }
        _ => {
            anyhow::bail!("give --from SOURCE --to DERIVED, or GLOB... --from-dir DIR (see --help)")
        }
    };

    report(&items, args.json)?;

    Ok(exit_code(&items, args.strict))
}

fn exit_code(items: &[Item], strict: bool) -> u8 {
    if items.iter().any(|i| i.status == "error") {
        return EXIT_ERROR;
    }
    if items.iter().any(|i| i.status == "refused") {
        return EXIT_REFUSED;
    }
    if strict
        && items
            .iter()
            .any(|i| matches!(i.status, "unpaired" | "ambiguous"))
    {
        return EXIT_UNPAIRED;
    }
    0
}

fn json_document(items: &[Item]) -> serde_json::Result<String> {
    match items {
        [one] => serde_json::to_string_pretty(one),
        many => serde_json::to_string_pretty(many),
    }
}

fn report(items: &[Item], json: bool) -> anyhow::Result<()> {
    if json {
        println!("{}", json_document(items)?);
        return Ok(());
    }

    for item in items {
        for warning in &item.warnings {
            eprintln!("warning: {}: {warning}", item.derived);
        }
        match item.status {
            "carried" => println!(
                "carried  {} <- {}  ({}, signer {}{})",
                item.out.as_deref().unwrap_or(&item.derived),
                item.source.as_deref().unwrap_or_default(),
                item.credential_status
                    .map_or("unverified", CredentialStatus::as_str),
                item.signer.as_deref().unwrap_or("unknown"),
                item.distance
                    .map(|d| format!(", distance {d}"))
                    .unwrap_or_default(),
            ),
            "composed" => println!(
                "composed {} <- {}  ({}, signer {})",
                item.out.as_deref().unwrap_or(&item.derived),
                item.sources.join(", "),
                item.credential_status
                    .map_or("unverified", CredentialStatus::as_str),
                item.signer.as_deref().unwrap_or("unknown"),
            ),
            "skipped" => println!(
                "skipped  {} (already carries {})",
                item.derived,
                item.source.as_deref().unwrap_or_default()
            ),
            other => eprintln!(
                "{other:<8} {}: {}",
                item.derived,
                item.message.as_deref().unwrap_or_default()
            ),
        }
    }
    Ok(())
}

fn batch(context: &Run<'_>, dir: &Path, patterns: &[String]) -> anyhow::Result<Vec<Item>> {
    let originals = index_originals(dir)?;
    let derived = crate::expand(patterns)?;

    let jobs: Vec<(PathBuf, Result<PathBuf, &'static str>)> = derived
        .into_iter()
        .map(|path| {
            let path = PathBuf::from(path);
            let pairing = original_for(&originals, &path);
            (path, pairing)
        })
        .collect();

    let workers = std::thread::available_parallelism()
        .map(usize::from)
        .unwrap_or(1)
        .clamp(1, MAX_WORKERS);
    let results: Vec<Mutex<Option<Item>>> = jobs.iter().map(|_| Mutex::new(None)).collect();
    let next = std::sync::atomic::AtomicUsize::new(0);

    std::thread::scope(|scope| {
        for _ in 0..workers.min(jobs.len().max(1)) {
            scope.spawn(|| loop {
                let at = next.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                let Some((derived, pairing)) = jobs.get(at) else {
                    break;
                };
                let item = match pairing {
                    Ok(source) => carry_one(context, source, derived, derived),
                    Err(status) => Item {
                        derived: derived.display().to_string(),
                        status,
                        message: Some(if *status == "unpaired" {
                            "no original with the same file name in --from-dir".into()
                        } else {
                            "more than one original with the same file name in --from-dir".into()
                        }),
                        ..Item::default()
                    },
                };
                if let Ok(mut slot) = results[at].lock() {
                    *slot = Some(item);
                }
            });
        }
    });

    Ok(results
        .into_iter()
        .filter_map(|slot| slot.into_inner().ok().flatten())
        .collect())
}

fn original_for(
    originals: &HashMap<String, Vec<PathBuf>>,
    derived: &Path,
) -> Result<PathBuf, &'static str> {
    let stem = derived
        .file_stem()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_default();
    let mut candidates = originals
        .get(&stem)
        .into_iter()
        .flatten()
        .filter(|p| !same_file(p, derived));
    match (candidates.next(), candidates.next()) {
        (None, _) => Err("unpaired"),
        (Some(one), None) => Ok(one.clone()),
        (Some(_), Some(_)) => Err("ambiguous"),
    }
}

fn same_file(a: &Path, b: &Path) -> bool {
    match (a.canonicalize(), b.canonicalize()) {
        (Ok(a), Ok(b)) => a == b,
        _ => a == b,
    }
}

fn index_originals(dir: &Path) -> anyhow::Result<HashMap<String, Vec<PathBuf>>> {
    let mut out: HashMap<String, Vec<PathBuf>> = HashMap::new();
    let pattern = format!("{}/**/*", glob::Pattern::escape(&dir.display().to_string()));
    for entry in glob::glob(&pattern)? {
        let path = entry?;
        if !path.is_file()
            || mime_from_extension(&path.to_string_lossy()) == "application/octet-stream"
        {
            continue;
        }
        if let Some(stem) = path.file_stem() {
            out.entry(stem.to_string_lossy().to_string())
                .or_default()
                .push(path);
        }
    }
    if out.is_empty() {
        anyhow::bail!("{} holds no media files", dir.display());
    }
    Ok(out)
}

fn carry_one(context: &Run<'_>, source_path: &Path, derived_path: &Path, out_path: &Path) -> Item {
    let mut item = Item {
        derived: derived_path.display().to_string(),
        source: Some(source_path.display().to_string()),
        warnings: context.warnings.clone(),
        ..Item::default()
    };
    let result = carry_inner(context, source_path, derived_path, out_path, &mut item);
    settle(item, result)
}

fn compose_one(
    context: &Run<'_>,
    sources: &[PathBuf],
    output_path: &Path,
    out_path: &Path,
    edited: bool,
) -> Item {
    let mut item = Item {
        derived: output_path.display().to_string(),
        sources: sources.iter().map(|p| p.display().to_string()).collect(),
        warnings: context.warnings.clone(),
        ..Item::default()
    };
    let result = compose_inner(context, sources, output_path, out_path, edited, &mut item);
    settle(item, result)
}

fn settle(mut item: Item, result: Result<(), Failure>) -> Item {
    match result {
        Ok(()) => {}
        Err(Failure::Refused(rule, message)) => {
            item.status = "refused";
            item.rule = rule;
            item.message = Some(message);
        }
        Err(Failure::Error(err)) => {
            item.status = "error";
            item.message = Some(format!("{err:#}"));
        }
    }
    item
}

pub fn read_media(path: &Path) -> anyhow::Result<Vec<u8>> {
    use std::io::Read;

    let file = std::fs::File::open(path).with_context(|| format!("reading {}", path.display()))?;
    let mut bytes = Vec::new();
    file.take(MAX_MEDIA_BYTES + 1)
        .read_to_end(&mut bytes)
        .with_context(|| format!("reading {}", path.display()))?;
    if bytes.len() as u64 > MAX_MEDIA_BYTES {
        anyhow::bail!(
            "{} exceeds the {MAX_MEDIA_BYTES} byte limit",
            path.display()
        );
    }
    Ok(bytes)
}

fn file_title(path: &Path) -> Option<String> {
    path.file_name().map(|n| n.to_string_lossy().into_owned())
}

fn compose_inner(
    context: &Run<'_>,
    sources: &[PathBuf],
    output_path: &Path,
    out_path: &Path,
    edited: bool,
    item: &mut Item,
) -> Result<(), Failure> {
    if sources.len() > MAX_COMPOSE_SOURCES {
        return Err(Failure::Error(anyhow!(
            "--compose takes at most {MAX_COMPOSE_SOURCES} sources, got {}",
            sources.len()
        )));
    }
    let read = sources
        .iter()
        .map(|path| {
            Ok((
                read_media(path)?,
                mime_from_extension(&path.to_string_lossy()),
                file_title(path).unwrap_or_else(|| "component".into()),
            ))
        })
        .collect::<anyhow::Result<Vec<_>>>()?;
    let output = read_media(output_path)?;
    let output_mime = mime_from_extension(&output_path.to_string_lossy());
    let components: Vec<carry::Component<'_>> = read
        .iter()
        .map(|(bytes, mime, title)| carry::Component { bytes, mime, title })
        .collect();

    if let Mode::Hosted { .. } = context.mode {
        item.warnings.push(format!(
            "hosted signing does not accept composites yet; signed with a local key. {SIGNER_HINT}"
        ));
    }
    let (signer, mode) = local_signer(context, item)?;
    let title = file_title(output_path);
    let outcome = carry::compose(
        &components,
        &output,
        output_mime,
        edited,
        title.as_deref(),
        signer.as_ref(),
    )?;
    let unsigned = components.len() - outcome.components_with_credentials;
    if unsigned > 0 {
        item.warnings.push(format!(
            "{unsigned} of {} sources carry no Content Credential; they are recorded as plain ingredients",
            components.len()
        ));
    }

    verify_and_write(context, &outcome.bytes, output_mime, out_path, item)?;
    item.status = "composed";
    item.signer_mode = Some(mode);
    item.actions = outcome.actions;
    Ok(())
}

fn verify_and_write(
    context: &Run<'_>,
    bytes: &[u8],
    mime: &str,
    out_path: &Path,
    item: &mut Item,
) -> Result<(), Failure> {
    let verified = context
        .verifier
        .verify(bytes, mime, &Options::default())
        .map_err(|e| Failure::Error(anyhow!("the signed file does not verify: {e}")))?;
    let status = verified.credential.status;
    if !matches!(
        status,
        CredentialStatus::ValidTrusted | CredentialStatus::ValidUntrusted
    ) {
        let codes: Vec<&str> = verified
            .validation
            .errors
            .iter()
            .map(|e| e.code.as_str())
            .collect();
        return Err(Failure::Error(anyhow!(
            "the signed file verifies as {} ({}); it was not written",
            status.as_str(),
            codes.join(", ")
        )));
    }

    write_atomically(out_path, bytes)?;
    item.out = Some(out_path.display().to_string());
    item.credential_status = Some(status);
    item.signer = verified
        .signer
        .and_then(|s| s.common_name.or(s.organization))
        .or(item.signer.take());
    Ok(())
}

enum Failure {
    Refused(Option<String>, String),
    Error(anyhow::Error),
}

impl From<anyhow::Error> for Failure {
    fn from(err: anyhow::Error) -> Self {
        Self::Error(err)
    }
}

impl From<CarryError> for Failure {
    fn from(err: CarryError) -> Self {
        if err.refused() {
            Self::Refused(err.rule().map(str::to_string), err.to_string())
        } else {
            Self::Error(anyhow!(err))
        }
    }
}

fn carry_inner(
    context: &Run<'_>,
    source_path: &Path,
    derived_path: &Path,
    out_path: &Path,
    item: &mut Item,
) -> Result<(), Failure> {
    let source = read_media(source_path)?;
    let derived = read_media(derived_path)?;
    let pair = Pair {
        source: &source,
        source_mime: mime_from_extension(&source_path.to_string_lossy()),
        derived: &derived,
        derived_mime: mime_from_extension(&derived_path.to_string_lossy()),
    };

    if carry::already_carried(
        pair.source,
        pair.source_mime,
        pair.derived,
        pair.derived_mime,
    ) {
        item.status = "skipped";
        return Ok(());
    }

    let options = CarryOptions {
        force: context.force,
        title: file_title(derived_path),
        max_pixels: Options::default().max_pixels,
    };

    let outcome = match &context.mode {
        Mode::Hosted { base, key } => match hosted(context, base, key, &pair, &options, item) {
            Ok(done) => done,
            Err(Hosted::Fallback(reason)) => {
                item.warnings.push(format!(
                    "hosted signing unavailable ({reason}); signed with a local key. {SIGNER_HINT}"
                ));
                local(context, &pair, &options, item)?
            }
            Err(Hosted::Failure(failure)) => return Err(failure),
        },
        _ => local(context, &pair, &options, item)?,
    };

    if !outcome.source_valid {
        item.warnings.push(
            "the source credential does not validate; it is carried as an ingredient with that status"
                .into(),
        );
    }

    verify_and_write(context, &outcome.bytes, pair.derived_mime, out_path, item)?;
    item.status = "carried";
    item.actions = outcome.actions;
    item.distance = outcome.distance;
    Ok(())
}

struct Pair<'a> {
    source: &'a [u8],
    source_mime: &'a str,
    derived: &'a [u8],
    derived_mime: &'a str,
}

impl Pair<'_> {
    fn carry(
        &self,
        signer: &dyn c2pa_check_core::c2pa::Signer,
        options: &CarryOptions,
    ) -> Result<CarryOutcome, CarryError> {
        carry::carry(
            self.source,
            self.source_mime,
            self.derived,
            self.derived_mime,
            signer,
            options,
        )
    }
}

fn local(
    context: &Run<'_>,
    pair: &Pair<'_>,
    options: &CarryOptions,
    item: &mut Item,
) -> Result<CarryOutcome, Failure> {
    let (signer, mode) = local_signer(context, item)?;
    let outcome = pair.carry(signer.as_ref(), options)?;
    item.signer_mode = Some(mode);
    Ok(outcome)
}

type BoxedSigner = Box<dyn c2pa_check_core::c2pa::Signer + Send + Sync>;

fn local_signer(
    context: &Run<'_>,
    item: &mut Item,
) -> Result<(BoxedSigner, &'static str), Failure> {
    Ok(match &context.mode {
        Mode::Own { chain, key } => (carry::local_signer(chain, key, context.tsa.clone())?, "own"),
        _ => (local_identity_signer(context, item)?, "local"),
    })
}

fn local_identity_signer(context: &Run<'_>, item: &mut Item) -> Result<BoxedSigner, Failure> {
    let mut slot = context
        .local
        .lock()
        .map_err(|_| Failure::Error(anyhow!("local identity lock poisoned")))?;
    let identity = match slot.take() {
        Some(identity) => identity,
        None => load_or_create_identity(item)?,
    };
    let signer = carry::local_signer(&identity.chain_pem, &identity.key_pem, context.tsa.clone());
    *slot = Some(identity);
    Ok(signer?)
}

fn identity_dir() -> Option<PathBuf> {
    std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".config")))
        .map(|base| base.join("c2pa-check").join("identity"))
}

fn load_or_create_identity(item: &mut Item) -> Result<LocalIdentity, Failure> {
    let dir = identity_dir();
    if let Some(dir) = &dir {
        let (cert, key) = (dir.join("cert.pem"), dir.join("key.pem"));
        if let (Ok(chain_pem), Ok(key_pem)) = (
            std::fs::read_to_string(&cert),
            std::fs::read_to_string(&key),
        ) {
            item.warnings.push(format!(
                "signed with the local key in {}; {SIGNER_HINT}",
                dir.display()
            ));
            return Ok(LocalIdentity { chain_pem, key_pem });
        }
    }

    let identity = carry::generate_identity(LOCAL_NAME)?;
    let saved = dir
        .as_ref()
        .is_some_and(|dir| save_identity(dir, &identity).is_ok());
    item.warnings.push(if saved {
        format!(
            "created a local signing key in {}; {SIGNER_HINT}",
            dir.as_ref()
                .map(|d| d.display().to_string())
                .unwrap_or_default()
        )
    } else {
        format!("signed with a one-time key that was not saved; {SIGNER_HINT}")
    });
    Ok(identity)
}

fn save_identity(dir: &Path, identity: &LocalIdentity) -> anyhow::Result<()> {
    std::fs::create_dir_all(dir)?;
    write_private(&dir.join("key.pem"), identity.key_pem.as_bytes())?;
    write_atomically(&dir.join("cert.pem"), identity.chain_pem.as_bytes())?;
    Ok(())
}

fn write_private(path: &Path, bytes: &[u8]) -> anyhow::Result<()> {
    use std::io::Write;

    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .with_context(|| format!("writing {}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    }
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

fn write_atomically(path: &Path, bytes: &[u8]) -> anyhow::Result<()> {
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| "carried".into());
    let temp = path.with_file_name(format!(".{name}.c2pa-check.tmp"));
    let written = std::fs::write(&temp, bytes)
        .with_context(|| format!("writing {}", temp.display()))
        .and_then(|()| {
            std::fs::rename(&temp, path).with_context(|| format!("replacing {}", path.display()))
        });
    if written.is_err() {
        std::fs::remove_file(&temp).ok();
    }
    written
}

enum Hosted {
    Fallback(String),
    Failure(Failure),
}

impl From<Failure> for Hosted {
    fn from(failure: Failure) -> Self {
        Self::Failure(failure)
    }
}

fn hosted(
    context: &Run<'_>,
    base: &str,
    key: &str,
    pair: &Pair<'_>,
    options: &CarryOptions,
    item: &mut Item,
) -> Result<CarryOutcome, Hosted> {
    let (chain, signer_name) = certificate(context, base, key)?;

    let placeholder = carry::new_placeholder().map_err(|e| Hosted::Failure(e.into()))?;
    let signer = DeferredSigner::new(chain, placeholder);
    let outcome = pair
        .carry(&signer, options)
        .map_err(|e| Hosted::Failure(e.into()))?;
    let tbs = signer.take_tbs().ok_or_else(|| {
        Hosted::Failure(Failure::Error(anyhow!(
            "the manifest was built without a signature request"
        )))
    })?;

    let boundary = boundary().map_err(|e| Hosted::Failure(Failure::Error(e)))?;
    let mut body = Vec::with_capacity(pair.source.len() + outcome.bytes.len() + tbs.len() + 1024);
    part(
        &mut body,
        &boundary,
        "source",
        Some(("source", pair.source_mime)),
        pair.source,
    );
    part(
        &mut body,
        &boundary,
        "derived",
        Some(("derived", pair.derived_mime)),
        &outcome.bytes,
    );
    part(
        &mut body,
        &boundary,
        "tbs",
        Some(("tbs", "application/octet-stream")),
        &tbs,
    );
    part(
        &mut body,
        &boundary,
        "placeholder",
        None,
        hex::encode(signer.placeholder()).as_bytes(),
    );
    body.extend_from_slice(format!("--{boundary}--\r\n").as_bytes());

    let response = call(
        &format!("{}/sign", base.trim_end_matches('/')),
        key,
        &format!("multipart/form-data; boundary={boundary}"),
        &body,
    )?;

    let signature = response
        .get("signature")
        .and_then(Value::as_str)
        .and_then(|text| base64::engine::general_purpose::STANDARD.decode(text).ok())
        .filter(|s| s.len() == PLACEHOLDER_LEN)
        .ok_or_else(|| Hosted::Fallback("the signing response had no signature".into()))?;
    let bytes = carry::patch_placeholder(&outcome.bytes, signer.placeholder(), &signature)
        .map_err(|e| Hosted::Failure(Failure::Error(anyhow!(e))))?;

    item.signer_mode = Some("hosted");
    item.carry_id = response
        .get("carry_id")
        .and_then(Value::as_str)
        .map(str::to_string);
    item.signer = response
        .get("signer_name")
        .and_then(Value::as_str)
        .filter(|name| !name.is_empty())
        .map(str::to_string)
        .or(signer_name);
    Ok(CarryOutcome { bytes, ..outcome })
}

type Certificate = (Vec<Vec<u8>>, Option<String>);

fn certificate(context: &Run<'_>, base: &str, key: &str) -> Result<Certificate, Hosted> {
    let mut cached = context
        .chain
        .lock()
        .map_err(|_| Hosted::Fallback("certificate cache lock poisoned".into()))?;
    if let Some(chain) = cached.as_ref() {
        return Ok(chain.clone());
    }

    let response = call(
        &format!("{}/sign/certificate", base.trim_end_matches('/')),
        key,
        "application/json",
        b"{}",
    )?;
    let pems: Vec<&str> = response
        .get("certificate_chain")
        .and_then(Value::as_array)
        .map(|items| items.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default();
    let chain = carry::pem_chain_to_der(&pems.concat())
        .map_err(|_| Hosted::Fallback("the certificate response had no chain".into()))?;
    let name = response
        .get("signer_name")
        .and_then(Value::as_str)
        .filter(|name| !name.is_empty())
        .map(str::to_string);
    *cached = Some((chain.clone(), name.clone()));
    Ok((chain, name))
}

fn part(body: &mut Vec<u8>, boundary: &str, name: &str, file: Option<(&str, &str)>, bytes: &[u8]) {
    body.extend_from_slice(format!("--{boundary}\r\n").as_bytes());
    match file {
        Some((filename, mime)) => body.extend_from_slice(
            format!(
                "Content-Disposition: form-data; name=\"{name}\"; filename=\"{filename}\"\r\nContent-Type: {mime}\r\n\r\n"
            )
            .as_bytes(),
        ),
        None => body.extend_from_slice(format!("Content-Disposition: form-data; name=\"{name}\"\r\n\r\n").as_bytes()),
    }
    body.extend_from_slice(bytes);
    body.extend_from_slice(b"\r\n");
}

fn boundary() -> anyhow::Result<String> {
    let mut random = [0u8; BOUNDARY_BYTES];
    getrandom::fill(&mut random).map_err(|e| anyhow!("no random source: {e}"))?;
    Ok(format!("c2pa-check-{}", hex::encode(random)))
}

fn call(url: &str, key: &str, content_type: &str, body: &[u8]) -> Result<Value, Hosted> {
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .timeout_global(Some(REQUEST_TIMEOUT))
        .http_status_as_error(false)
        .build()
        .into();

    let mut last = String::new();
    for attempt in 0..2 {
        if attempt > 0 {
            std::thread::sleep(jitter());
        }
        let sent = agent
            .post(url)
            .header("Authorization", &format!("Bearer {key}"))
            .header("Content-Type", content_type)
            .header(
                "User-Agent",
                &format!("c2pa-check/{}", env!("CARGO_PKG_VERSION")),
            )
            .send(body);
        let mut response = match sent {
            Ok(response) => response,
            Err(err) => {
                last = network_reason(&err);
                continue;
            }
        };
        let status = response.status().as_u16();
        let bytes = response.body_mut().read_to_vec().unwrap_or_default();
        let value: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
        if (200..300).contains(&status) {
            return Ok(value);
        }
        let code = value
            .pointer("/error/code")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string();
        if code == "carry_rejected" {
            let rule = value
                .pointer("/error/details/rule")
                .and_then(Value::as_str)
                .map(str::to_string);
            let message = value
                .pointer("/error/message")
                .and_then(Value::as_str)
                .unwrap_or("c2pa.design refused to sign this carry")
                .to_string();
            return Err(Hosted::Failure(Failure::Refused(rule, message)));
        }
        if status >= 500 {
            last = format!("HTTP {status}");
            continue;
        }
        if status == 401 || status == 403 || FALLBACK_CODES.contains(&code.as_str()) {
            return Err(Hosted::Fallback(if code.is_empty() {
                format!("HTTP {status}")
            } else {
                code
            }));
        }
        return Err(Hosted::Failure(Failure::Error(anyhow!(
            "c2pa.design answered HTTP {status} {code}"
        ))));
    }
    Err(Hosted::Fallback(last))
}

fn network_reason(err: &ureq::Error) -> String {
    match err {
        ureq::Error::Timeout(_) => "timeout".into(),
        other => format!("network: {other}"),
    }
}

fn jitter() -> Duration {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or_default();
    Duration::from_millis(200 + u64::from(nanos % 500))
}

fn pem_from_env(name: &str) -> anyhow::Result<Option<(String, Option<PathBuf>)>> {
    if let Some(path) = env::value(&format!("{name}_FILE")) {
        let path = PathBuf::from(path);
        let text = std::fs::read_to_string(&path)
            .with_context(|| format!("{name}_FILE {}", path.display()))?;
        return Ok(Some((text, Some(path))));
    }
    match env::value(name) {
        Some(value) if value.contains("-----BEGIN") => Ok(Some((value, None))),
        Some(path) => {
            let path = PathBuf::from(path);
            let text = std::fs::read_to_string(&path)
                .with_context(|| format!("{name} {}", path.display()))?;
            Ok(Some((text, Some(path))))
        }
        None => Ok(None),
    }
}

fn mode_from_env() -> (Mode, Vec<String>) {
    let mut warnings = Vec::new();
    match (
        pem_from_env("C2PA_SIGN_CERT"),
        pem_from_env("C2PA_SIGN_KEY"),
    ) {
        (Ok(Some((chain, _))), Ok(Some((key, key_path)))) => {
            if let Some(path) = key_path {
                if loose_permissions(&path) {
                    warnings.push(format!(
                        "{} is readable by other users; chmod 600 it",
                        path.display()
                    ));
                }
            }
            return (Mode::Own { chain, key }, warnings);
        }
        (Ok(Some(_)), Ok(None)) | (Ok(None), Ok(Some(_))) => {
            warnings
                .push("C2PA_SIGN_CERT and C2PA_SIGN_KEY must both be set; ignoring them".into());
        }
        (Err(err), _) | (_, Err(err)) => {
            warnings.push(format!("{err:#}; ignoring the signing certificate"))
        }
        _ => {}
    }
    if let Some(key) = env::api_key() {
        return (
            Mode::Hosted {
                base: env::api_base(),
                key,
            },
            warnings,
        );
    }
    (Mode::Local, warnings)
}

fn loose_permissions(path: &Path) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::metadata(path).is_ok_and(|m| m.permissions().mode() & 0o077 != 0)
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        false
    }
}

pub fn keygen(args: KeygenArgs) -> anyhow::Result<u8> {
    let identity = carry::generate_identity(&args.name)?;
    std::fs::create_dir_all(&args.out_dir)?;
    let cert = args.out_dir.join("cert.pem");
    let key = args.out_dir.join("key.pem");
    write_atomically(&cert, identity.chain_pem.as_bytes())?;
    write_private(&key, identity.key_pem.as_bytes())?;

    println!(
        "wrote {} (certificate chain) and {} (private key, mode 600)",
        cert.display(),
        key.display()
    );
    println!();
    println!("Store both as CI secrets named C2PA_SIGN_CERT and C2PA_SIGN_KEY, then:");
    println!();
    println!("  GitHub Actions:");
    println!("    - run: npx -y c2pa-check carry --from src/hero.png --to public/hero.webp");
    println!("      env:");
    println!("        C2PA_SIGN_CERT: ${{{{ secrets.C2PA_SIGN_CERT }}}}");
    println!("        C2PA_SIGN_KEY: ${{{{ secrets.C2PA_SIGN_KEY }}}}");
    println!();
    println!("  Docker (the key never enters an image layer):");
    println!("    RUN --mount=type=secret,id=c2pa_cert,env=C2PA_SIGN_CERT \\");
    println!("        --mount=type=secret,id=c2pa_key,env=C2PA_SIGN_KEY \\");
    println!("        npx -y c2pa-check carry --from src/hero.png --to public/hero.webp");
    println!(
        "    docker build --secret id=c2pa_cert,src=cert.pem --secret id=c2pa_key,src=key.pem ."
    );
    println!();
    println!(
        "Never COPY or ARG the key into an image. This certificate is not on the C2PA trust list:"
    );
    println!("files signed with it verify as valid_untrusted.");

    if args.stdout {
        println!();
        print!("{}", identity.key_pem);
    }

    Ok(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_server::serve;

    fn item(status: &'static str) -> Item {
        Item {
            status,
            ..Item::default()
        }
    }

    #[test]
    fn errors_win_over_refusals_and_refusals_over_success() {
        assert_eq!(exit_code(&[item("carried"), item("skipped")], false), 0);
        assert_eq!(
            exit_code(&[item("carried"), item("refused")], false),
            EXIT_REFUSED
        );
        assert_eq!(
            exit_code(&[item("refused"), item("error")], false),
            EXIT_ERROR
        );
    }

    #[test]
    fn unpaired_files_fail_only_in_strict_mode() {
        assert_eq!(exit_code(&[item("carried"), item("unpaired")], false), 0);
        assert_eq!(exit_code(&[item("ambiguous")], true), EXIT_UNPAIRED);
    }

    #[test]
    fn a_multipart_part_carries_its_name_type_and_bytes() {
        let mut body = Vec::new();
        part(
            &mut body,
            "b",
            "derived",
            Some(("derived", "image/webp")),
            b"RIFF",
        );
        part(&mut body, "b", "placeholder", None, b"ab");
        let text = String::from_utf8_lossy(&body);

        assert!(text.contains(
            "name=\"derived\"; filename=\"derived\"\r\nContent-Type: image/webp\r\n\r\nRIFF\r\n"
        ));
        assert!(text.contains("name=\"placeholder\"\r\n\r\nab\r\n"));
    }

    #[test]
    fn the_key_is_never_written_to_a_report() {
        let mut report = item("carried");
        report.warnings.push(SIGNER_HINT.into());
        let text = serde_json::to_string(&report).unwrap();

        assert!(!text.contains("PRIVATE KEY"));
        assert!(!text.contains("Bearer"));
    }

    #[test]
    fn a_private_file_is_written_owner_only() {
        let dir = std::env::temp_dir().join(format!("c2pa-check-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("key.pem");

        write_private(&path, b"secret").unwrap();

        assert!(!loose_permissions(&path));
        std::fs::remove_dir_all(&dir).ok();
    }

    fn scratch(name: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("c2pa-check-carry-{name}-{}", std::process::id()));
        std::fs::remove_dir_all(&dir).ok();
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn a_derived_file_pairs_with_the_one_original_of_its_stem() {
        let mut originals: HashMap<String, Vec<PathBuf>> = HashMap::new();
        originals.insert("hero".into(), vec![PathBuf::from("src/hero.png")]);
        originals.insert(
            "logo".into(),
            vec![PathBuf::from("src/logo.png"), PathBuf::from("src/logo.jpg")],
        );
        originals.insert("self".into(), vec![PathBuf::from("out/self.webp")]);

        assert_eq!(
            original_for(&originals, Path::new("out/hero.webp")),
            Ok(PathBuf::from("src/hero.png"))
        );
        assert_eq!(
            original_for(&originals, Path::new("out/logo.webp")),
            Err("ambiguous")
        );
        assert_eq!(
            original_for(&originals, Path::new("out/other.webp")),
            Err("unpaired")
        );
        assert_eq!(
            original_for(&originals, Path::new("out/self.webp")),
            Err("unpaired")
        );
    }

    #[test]
    fn originals_are_indexed_by_stem_and_non_media_is_skipped() {
        let dir = scratch("index");
        std::fs::create_dir_all(dir.join("nested")).unwrap();
        for name in ["a.png", "nested/b.jpg", "notes.txt"] {
            std::fs::write(dir.join(name), b"x").unwrap();
        }

        let index = index_originals(&dir).unwrap();
        let empty = scratch("index-empty");
        let none = index_originals(&empty);
        std::fs::remove_dir_all(&dir).ok();
        std::fs::remove_dir_all(&empty).ok();

        let mut stems: Vec<&String> = index.keys().collect();
        stems.sort();
        assert_eq!(stems, ["a", "b"]);
        assert!(none.is_err());
    }

    #[test]
    fn one_result_is_an_object_and_several_are_an_array() {
        let one: Value = serde_json::from_str(&json_document(&[item("carried")]).unwrap()).unwrap();
        let two: Value =
            serde_json::from_str(&json_document(&[item("carried"), item("refused")]).unwrap())
                .unwrap();

        assert_eq!(one["status"], "carried");
        assert_eq!(two.as_array().map(Vec::len), Some(2));
    }

    #[test]
    fn an_atomic_write_replaces_the_file_and_leaves_no_temp() {
        let dir = scratch("atomic");
        let path = dir.join("hero.webp");
        std::fs::write(&path, b"old").unwrap();

        write_atomically(&path, b"new").unwrap();
        let missing = write_atomically(&dir.join("absent/hero.webp"), b"x");
        let left: Vec<_> = std::fs::read_dir(&dir).unwrap().flatten().collect();
        let content = std::fs::read(&path).unwrap();
        std::fs::remove_dir_all(&dir).ok();

        assert_eq!(content, b"new");
        assert!(missing.is_err());
        assert_eq!(left.len(), 1);
    }

    #[cfg(unix)]
    #[test]
    fn a_private_file_that_existed_with_loose_permissions_is_tightened() {
        use std::os::unix::fs::PermissionsExt;

        let dir = scratch("loose");
        let path = dir.join("key.pem");
        std::fs::write(&path, b"old").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();

        write_private(&path, b"secret").unwrap();
        let loose = loose_permissions(&path);
        std::fs::remove_dir_all(&dir).ok();

        assert!(!loose);
    }

    #[test]
    fn boundaries_are_random() {
        let a = boundary().unwrap();
        let b = boundary().unwrap();

        assert_ne!(a, b);
        assert_eq!(a.len(), "c2pa-check-".len() + 2 * BOUNDARY_BYTES);
    }

    fn outcome_of(result: Result<Value, Hosted>) -> String {
        match result {
            Ok(value) => format!("ok {value}"),
            Err(Hosted::Fallback(reason)) => format!("fallback {reason}"),
            Err(Hosted::Failure(Failure::Refused(rule, message))) => {
                format!("refused {} {message}", rule.unwrap_or_default())
            }
            Err(Hosted::Failure(Failure::Error(err))) => format!("error {err}"),
        }
    }

    #[test]
    fn api_answers_map_to_success_fallback_refusal_or_error() {
        let cases = [
            (1, 200, r#"{"ok":true}"#, r#"ok {"ok":true}"#),
            (1, 401, "", "fallback HTTP 401"),
            (
                1,
                429,
                r#"{"error":{"code":"rate_limited"}}"#,
                "fallback rate_limited",
            ),
            (
                1,
                422,
                r#"{"error":{"code":"carry_rejected","message":"not the same picture","details":{"rule":"different_picture"}}}"#,
                "refused different_picture not the same picture",
            ),
            (
                1,
                400,
                r#"{"error":{"code":"bad_request"}}"#,
                "error c2pa.design answered HTTP 400 bad_request",
            ),
            (2, 503, "{}", "fallback HTTP 503"),
        ];

        for (requests, status, body, expected) in cases {
            let answer = body.to_string();
            let (base, server) = serve(requests, move |_| (status, answer.clone()));

            let got = outcome_of(call(
                &format!("{base}/sign"),
                "key",
                "application/json",
                b"{}",
            ));
            let paths = server.join().unwrap();

            assert_eq!(got, expected);
            assert_eq!(paths.len(), requests);
        }
    }

    #[test]
    fn an_unreachable_api_falls_back() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        drop(listener);

        let got = outcome_of(call(
            &format!("http://{address}/v1/sign"),
            "key",
            "application/json",
            b"{}",
        ));

        assert!(got.starts_with("fallback network"), "{got}");
    }

    fn picture() -> image::DynamicImage {
        image::DynamicImage::ImageRgb8(image::RgbImage::from_fn(400, 300, |x, y| {
            let fx = x as f32 / 400.0;
            let fy = y as f32 / 300.0;
            let v = ((fx * 17.0).sin() * (fy * 11.0).cos() + (fx * fy * 23.0).sin()) * 60.0 + 128.0;
            image::Rgb([v as u8, (v * 0.7 + fx * 60.0) as u8, (255.0 - v) as u8])
        }))
    }

    fn encoded(image: &image::DynamicImage, format: image::ImageFormat) -> Vec<u8> {
        let mut out = std::io::Cursor::new(Vec::new());
        image.write_to(&mut out, format).unwrap();
        out.into_inner()
    }

    fn signed_png(identity: &LocalIdentity) -> Vec<u8> {
        let signer = carry::local_signer(&identity.chain_pem, &identity.key_pem, None).unwrap();
        let context = c2pa::Context::new()
            .with_settings(serde_json::json!({"builder": {"thumbnail": {"enabled": false}}}))
            .unwrap();
        let mut builder = c2pa::Builder::from_context(context)
            .with_definition(serde_json::json!({
                "claim_generator_info": [{"name": "test-generator", "version": "1"}],
                "title": "generated.png",
                "format": "image/png",
                "assertions": [{"label": "c2pa.actions", "data": {"actions": [{"action": "c2pa.created", "digitalSourceType": "http://cv.iptc.org/newscodes/digitalsourcetype/trainedAlgorithmicMedia"}]}}]
            }))
            .unwrap();
        let mut out = std::io::Cursor::new(Vec::new());
        builder
            .sign(
                signer.as_ref(),
                "image/png",
                &mut std::io::Cursor::new(encoded(&picture(), image::ImageFormat::Png)),
                &mut out,
            )
            .unwrap();
        out.into_inner()
    }

    fn multipart_field<'a>(body: &'a [u8], boundary: &str, name: &str) -> &'a [u8] {
        let marker = format!("name=\"{name}\"");
        let start = body
            .windows(marker.len())
            .position(|w| w == marker.as_bytes())
            .expect("the field is present");
        let content = start
            + body[start..]
                .windows(4)
                .position(|w| w == b"\r\n\r\n")
                .expect("the part has headers")
            + 4;
        let end_marker = format!("\r\n--{boundary}");
        let end = content
            + body[content..]
                .windows(end_marker.len())
                .position(|w| w == end_marker.as_bytes())
                .expect("the part ends");
        &body[content..end]
    }

    #[test]
    fn a_hosted_carry_patches_the_returned_signature_and_verifies() {
        use c2pa::Signer as _;

        let organization = carry::generate_identity("acme.example via c2pa.design").unwrap();
        let chain_pem = organization.chain_pem.clone();
        let key_pem = organization.key_pem.clone();
        let (base, server) = serve(2, move |request| {
            if request.path.ends_with("/sign/certificate") {
                return (
                    200,
                    serde_json::json!({
                        "certificate_chain": [chain_pem],
                        "signer_name": "acme.example via c2pa.design"
                    })
                    .to_string(),
                );
            }
            let boundary = request
                .content_type
                .split("boundary=")
                .nth(1)
                .unwrap_or_default();
            let tbs = multipart_field(&request.body, boundary, "tbs");
            assert_eq!(
                multipart_field(&request.body, boundary, "placeholder").len(),
                128
            );
            let signature = carry::local_signer(&chain_pem, &key_pem, None)
                .unwrap()
                .sign(tbs)
                .unwrap();
            (
                200,
                serde_json::json!({
                    "signature": base64::engine::general_purpose::STANDARD.encode(signature),
                    "carry_id": "carry_1",
                    "signer_name": "acme.example via c2pa.design"
                })
                .to_string(),
            )
        });

        let dir = scratch("hosted");
        let generator = carry::generate_identity("Test Generator").unwrap();
        std::fs::write(dir.join("hero.png"), signed_png(&generator)).unwrap();
        std::fs::write(
            dir.join("hero.webp"),
            encoded(&picture(), image::ImageFormat::WebP),
        )
        .unwrap();
        let verifier = Verifier::new(
            &c2pa_check_core::TrustBundle::default(),
            c2pa_check_core::report::TrustSelector::None,
        )
        .unwrap();
        let context = Run {
            verifier: &verifier,
            mode: Mode::Hosted {
                base,
                key: "c2pa_test_key".into(),
            },
            tsa: None,
            force: false,
            local: Mutex::new(None),
            chain: Mutex::new(None),
            warnings: Vec::new(),
        };

        let item = carry_one(
            &context,
            &dir.join("hero.png"),
            &dir.join("hero.webp"),
            &dir.join("hero.carried.webp"),
        );
        let paths = server.join().unwrap();
        let carried = std::fs::read(dir.join("hero.carried.webp"));
        std::fs::remove_dir_all(&dir).ok();

        assert_eq!(item.status, "carried", "{:?}", item.message);
        assert_eq!(item.signer_mode, Some("hosted"));
        assert_eq!(item.carry_id.as_deref(), Some("carry_1"));
        assert_eq!(item.signer.as_deref(), Some("acme.example via c2pa.design"));
        assert_eq!(
            item.credential_status,
            Some(CredentialStatus::ValidUntrusted)
        );
        assert_eq!(item.actions, ["c2pa.opened", "c2pa.transcoded"]);
        assert!(item.warnings.is_empty(), "{:?}", item.warnings);
        assert_eq!(paths, ["/v1/sign/certificate", "/v1/sign"]);
        let report = verifier
            .verify(&carried.unwrap(), "image/webp", &Options::default())
            .unwrap();
        assert_eq!(report.ingredients.len(), 1);
    }

    #[test]
    fn a_composite_is_signed_as_a_new_work_with_every_source_as_a_component() {
        let dir = scratch("compose");
        let generator = carry::generate_identity("Test Generator").unwrap();
        std::fs::write(dir.join("a.png"), signed_png(&generator)).unwrap();
        std::fs::write(
            dir.join("b.png"),
            encoded(&picture(), image::ImageFormat::Png),
        )
        .unwrap();
        std::fs::write(
            dir.join("atlas.webp"),
            encoded(&picture(), image::ImageFormat::WebP),
        )
        .unwrap();
        let verifier = no_trust_verifier();
        let context = own_context(&verifier);
        let sources = [dir.join("a.png"), dir.join("b.png")];

        let created = compose_one(
            &context,
            &sources,
            &dir.join("atlas.webp"),
            &dir.join("created.webp"),
            false,
        );
        let edited = compose_one(
            &context,
            &sources,
            &dir.join("atlas.webp"),
            &dir.join("edited.webp"),
            true,
        );
        let created_bytes = std::fs::read(dir.join("created.webp"));
        let edited_bytes = std::fs::read(dir.join("edited.webp"));
        std::fs::remove_dir_all(&dir).ok();

        assert_eq!(created.status, "composed", "{:?}", created.message);
        assert_eq!(edited.status, "composed", "{:?}", edited.message);
        assert_eq!(created.signer_mode, Some("own"));
        assert_eq!(created.actions, ["c2pa.created", "c2pa.placed"]);
        assert_eq!(
            edited.actions,
            ["c2pa.opened", "c2pa.edited", "c2pa.placed"]
        );
        assert_eq!(
            created.credential_status,
            Some(CredentialStatus::ValidUntrusted)
        );
        assert!(created
            .warnings
            .iter()
            .any(|w| w.contains("1 of 2 sources")));
        let report = verifier
            .verify(
                &created_bytes.unwrap(),
                "image/webp",
                &Options {
                    include_raw: true,
                    ..Options::default()
                },
            )
            .unwrap();
        assert_eq!(report.ingredients.len(), 2);
        let raw = serde_json::to_string(&report.raw_manifest_store).unwrap();
        assert_eq!(raw.matches("componentOf").count(), 2);
        assert!(raw.contains("c2pa.created"));
        assert!(!raw.contains("c2pa.edited"));

        let edited_report = verifier
            .verify(
                &edited_bytes.unwrap(),
                "image/webp",
                &Options {
                    include_raw: true,
                    ..Options::default()
                },
            )
            .unwrap();
        let edited_raw = serde_json::to_string(&edited_report.raw_manifest_store).unwrap();
        assert_eq!(edited_raw.matches("parentOf").count(), 1);
        assert_eq!(edited_raw.matches("componentOf").count(), 1);
        assert!(edited_raw.contains("c2pa.edited"));
    }

    fn own_context(verifier: &Verifier) -> Run<'_> {
        let own = carry::generate_identity("acme.example").unwrap();
        Run {
            verifier,
            mode: Mode::Own {
                chain: own.chain_pem,
                key: own.key_pem,
            },
            tsa: None,
            force: false,
            local: Mutex::new(None),
            chain: Mutex::new(None),
            warnings: Vec::new(),
        }
    }

    fn no_trust_verifier() -> Verifier {
        Verifier::new(
            &c2pa_check_core::TrustBundle::default(),
            c2pa_check_core::report::TrustSelector::None,
        )
        .unwrap()
    }

    #[test]
    fn a_different_picture_is_refused_with_a_rule_and_exit_5() {
        let dir = scratch("refused");
        let generator = carry::generate_identity("Test Generator").unwrap();
        std::fs::write(dir.join("hero.png"), signed_png(&generator)).unwrap();
        let mut other = picture();
        other.invert();
        std::fs::write(
            dir.join("hero.webp"),
            encoded(&other.fliph(), image::ImageFormat::WebP),
        )
        .unwrap();
        let verifier = no_trust_verifier();
        let context = own_context(&verifier);

        let item = carry_one(
            &context,
            &dir.join("hero.png"),
            &dir.join("hero.webp"),
            &dir.join("out.webp"),
        );
        let written = dir.join("out.webp").exists();
        std::fs::remove_dir_all(&dir).ok();
        let items = [item];
        let value: Value = serde_json::from_str(&json_document(&items).unwrap()).unwrap();

        assert!(!written);
        assert_eq!(value["status"], "refused");
        assert_eq!(value["rule"], "different_picture");
        assert!(value["message"].as_str().unwrap().contains("PDQ distance"));
        assert!(value["source"].as_str().unwrap().ends_with("hero.png"));
        assert!(value["derived"].as_str().unwrap().ends_with("hero.webp"));
        assert!(value.get("output").is_none());
        assert!(value.get("signer_mode").is_none());
        assert!(value.get("outcome").is_none());
        assert_eq!(exit_code(&items, false), EXIT_REFUSED);
        assert_eq!(EXIT_REFUSED, 5);
    }

    #[test]
    fn a_carried_file_reports_output_signer_and_credential_status_in_json() {
        let dir = scratch("carried-json");
        let generator = carry::generate_identity("Test Generator").unwrap();
        std::fs::write(dir.join("hero.png"), signed_png(&generator)).unwrap();
        std::fs::write(
            dir.join("hero.webp"),
            encoded(&picture(), image::ImageFormat::WebP),
        )
        .unwrap();
        let verifier = no_trust_verifier();
        let context = own_context(&verifier);

        let item = carry_one(
            &context,
            &dir.join("hero.png"),
            &dir.join("hero.webp"),
            &dir.join("out.webp"),
        );
        std::fs::remove_dir_all(&dir).ok();
        let items = [item];
        let value: Value = serde_json::from_str(&json_document(&items).unwrap()).unwrap();

        assert_eq!(value["status"], "carried", "{value}");
        assert!(value["output"].as_str().unwrap().ends_with("out.webp"));
        assert_eq!(value["signer_mode"], "own");
        assert_eq!(value["signer"], "acme.example");
        assert_eq!(value["credential_status"], "valid_untrusted");
        assert_eq!(value["distance"], 0);
        assert_eq!(value["actions"][0], "c2pa.opened");
        assert_eq!(exit_code(&items, false), 0);
    }

    #[test]
    fn compose_rejects_too_many_sources_before_reading_any() {
        let verifier = no_trust_verifier();
        let context = own_context(&verifier);
        let sources = vec![PathBuf::from("/nonexistent/a.png"); MAX_COMPOSE_SOURCES + 1];

        let item = compose_one(
            &context,
            &sources,
            Path::new("/nonexistent/atlas.png"),
            Path::new("/nonexistent/out.png"),
            false,
        );

        assert_eq!(item.status, "error");
        assert!(item.message.unwrap().contains("at most"));
    }

    #[test]
    fn compose_reports_a_missing_source_as_an_error() {
        let verifier = no_trust_verifier();
        let context = own_context(&verifier);

        let item = compose_one(
            &context,
            &[PathBuf::from("/nonexistent/a.png")],
            Path::new("/nonexistent/atlas.png"),
            Path::new("/nonexistent/out.png"),
            false,
        );

        assert_eq!(item.status, "error");
        assert!(item.message.unwrap().contains("reading /nonexistent/a.png"));
    }

    #[test]
    fn media_larger_than_the_cap_is_not_read() {
        let dir = scratch("oversized");
        let path = dir.join("big.png");
        std::fs::File::create(&path)
            .unwrap()
            .set_len(MAX_MEDIA_BYTES + 1)
            .unwrap();
        let small = dir.join("small.png");
        std::fs::write(&small, b"png").unwrap();

        let big = read_media(&path);
        let ok = read_media(&small);
        std::fs::remove_dir_all(&dir).ok();

        assert!(big.unwrap_err().to_string().contains("byte limit"));
        assert_eq!(ok.unwrap(), b"png");
    }

    #[test]
    fn the_json_report_names_status_rule_message_source_and_output() {
        let items = vec![Item {
            derived: "hero.webp".into(),
            source: Some("hero.png".into()),
            out: Some("hero.webp".into()),
            status: "refused",
            rule: Some("different_picture".into()),
            message: Some("not the same picture".into()),
            ..Item::default()
        }];
        let value: Value = serde_json::from_str(&json_document(&items).unwrap()).unwrap();

        assert_eq!(value["status"], "refused");
        assert_eq!(value["rule"], "different_picture");
        assert_eq!(value["message"], "not the same picture");
        assert_eq!(value["source"], "hero.png");
        assert_eq!(value["output"], "hero.webp");
        assert_eq!(exit_code(&items, false), 5);
    }
}

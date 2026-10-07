use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

const MAX_XMP_PACKETS: usize = 8;
const MAX_XMP_DEPTH: usize = 256;
const MAX_VALUE_CHARS: usize = 256;
const MAX_IFD_ENTRIES: usize = 1024;
const MAX_SEGMENTS: usize = 4096;

const XMP_OPEN: &[u8] = b"<x:xmpmeta";
const XMP_CLOSE: &[u8] = b"</x:xmpmeta>";
const EXIF_PREFIX: &[u8] = b"Exif\0\0";
const PHOTOSHOP_PREFIX: &[u8] = b"Photoshop 3.0\0";

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Metadata {
    pub four_cs_score: u8,
    pub fields: Vec<String>,
    pub digital_source_type: Option<String>,
    pub ai_system_used: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Field {
    AIPromptInformation,
    AIPromptWriterName,
    AISystemUsed,
    AISystemVersionUsed,
    AltTextAccessibility,
    CaptionDescription,
    Copyright,
    Creator,
    CreditLine,
    DataMining,
    DateCreated,
    DigitalSourceType,
    ExtendedDescriptionAccessibility,
    Genre,
    Keywords,
    LicensorName,
    LicensorURL,
    LocationCreated,
    LocationShown,
    ObjectName,
    Source,
    UsageTerms,
    WebStatement,
}

impl Field {
    pub fn name(self) -> &'static str {
        match self {
            Self::AIPromptInformation => "AIPromptInformation",
            Self::AIPromptWriterName => "AIPromptWriterName",
            Self::AISystemUsed => "AISystemUsed",
            Self::AISystemVersionUsed => "AISystemVersionUsed",
            Self::AltTextAccessibility => "AltTextAccessibility",
            Self::CaptionDescription => "CaptionDescription",
            Self::Copyright => "Copyright",
            Self::Creator => "Creator",
            Self::CreditLine => "CreditLine",
            Self::DataMining => "DataMining",
            Self::DateCreated => "DateCreated",
            Self::DigitalSourceType => "DigitalSourceType",
            Self::ExtendedDescriptionAccessibility => "ExtendedDescriptionAccessibility",
            Self::Genre => "Genre",
            Self::Keywords => "Keywords",
            Self::LicensorName => "LicensorName",
            Self::LicensorURL => "LicensorURL",
            Self::LocationCreated => "LocationCreated",
            Self::LocationShown => "LocationShown",
            Self::ObjectName => "ObjectName",
            Self::Source => "Source",
            Self::UsageTerms => "UsageTerms",
            Self::WebStatement => "WebStatement",
        }
    }

    fn scored(self) -> bool {
        matches!(
            self,
            Self::Creator | Self::Copyright | Self::CaptionDescription | Self::CreditLine
        )
    }
}

const XMP_FIELDS: &[(&str, Field)] = &[
    ("dc:creator", Field::Creator),
    ("dc:rights", Field::Copyright),
    ("dc:description", Field::CaptionDescription),
    ("photoshop:Credit", Field::CreditLine),
    ("photoshop:DateCreated", Field::DateCreated),
    ("dc:subject", Field::Keywords),
    ("photoshop:Source", Field::Source),
    ("dc:title", Field::ObjectName),
    ("xmpRights:UsageTerms", Field::UsageTerms),
    ("xmpRights:WebStatement", Field::WebStatement),
    ("Iptc4xmpExt:DigitalSourceType", Field::DigitalSourceType),
    ("Iptc4xmpExt:AISystemUsed", Field::AISystemUsed),
    (
        "Iptc4xmpExt:AISystemVersionUsed",
        Field::AISystemVersionUsed,
    ),
    (
        "Iptc4xmpExt:AIPromptInformation",
        Field::AIPromptInformation,
    ),
    ("Iptc4xmpExt:AIPromptWriterName", Field::AIPromptWriterName),
    (
        "Iptc4xmpCore:AltTextAccessibility",
        Field::AltTextAccessibility,
    ),
    (
        "Iptc4xmpCore:ExtDescrAccessibility",
        Field::ExtendedDescriptionAccessibility,
    ),
    ("Iptc4xmpExt:LocationCreated", Field::LocationCreated),
    ("Iptc4xmpExt:LocationShown", Field::LocationShown),
    ("plus:DataMining", Field::DataMining),
    ("plus:LicensorName", Field::LicensorName),
    ("plus:LicensorURL", Field::LicensorURL),
    ("Iptc4xmpCore:IntellectualGenre", Field::Genre),
];

const IIM_FIELDS: &[(u8, Field)] = &[
    (5, Field::ObjectName),
    (25, Field::Keywords),
    (55, Field::DateCreated),
    (80, Field::Creator),
    (110, Field::CreditLine),
    (115, Field::Source),
    (116, Field::Copyright),
    (120, Field::CaptionDescription),
];

const EXIF_FIELDS: &[(u16, Field)] = &[
    (0x013B, Field::Creator),
    (0x8298, Field::Copyright),
    (0x010E, Field::CaptionDescription),
    (0x9003, Field::DateCreated),
];

const TAG_EXIF_IFD: u16 = 0x8769;
const TAG_IPTC: u16 = 0x83BB;

const IGNORED_ATTRIBUTES: &[&str] = &["rdf:parseType", "xml:lang", "rdf:about", "x:xmptk"];

#[derive(Debug, Default)]
struct Found {
    fields: BTreeSet<Field>,
    digital_source_type: Option<String>,
    ai_system_used: Option<String>,
}

impl Found {
    fn mark(&mut self, field: Field, value: &str) {
        self.fields.insert(field);
        let slot = match field {
            Field::DigitalSourceType => &mut self.digital_source_type,
            Field::AISystemUsed => &mut self.ai_system_used,
            _ => return,
        };
        if slot.is_none() {
            *slot = Some(bounded(&unescape(value.trim())));
        }
    }

    fn into_metadata(self) -> Metadata {
        let score = self.fields.iter().filter(|f| f.scored()).count() * 25;

        Metadata {
            four_cs_score: u8::try_from(score).unwrap_or(100),
            fields: self.fields.iter().map(|f| f.name().to_string()).collect(),
            digital_source_type: self.digital_source_type.map(|v| last_segment(&v)),
            ai_system_used: self.ai_system_used,
        }
    }
}

pub fn applies_to(mime_type: &str) -> bool {
    mime_type.starts_with("image/")
}

pub fn extract(bytes: &[u8], mime_type: &str) -> Metadata {
    let mut found = Found::default();

    for tiff in exif_blocks(bytes, mime_type) {
        scan_tiff(tiff, &mut found);
    }
    for iim in iim_blocks(bytes) {
        scan_iim(iim, &mut found);
    }
    for packet in xmp_packets(bytes) {
        scan_xmp(&String::from_utf8_lossy(packet), &mut found);
    }

    found.into_metadata()
}

fn exif_blocks<'a>(bytes: &'a [u8], mime_type: &str) -> Vec<&'a [u8]> {
    if is_tiff(bytes) {
        return vec![bytes];
    }
    if bytes.starts_with(&[0xFF, 0xD8]) {
        return jpeg_segments(bytes)
            .into_iter()
            .filter(|(marker, _)| *marker == 0xE1)
            .filter_map(|(_, payload)| payload.strip_prefix(EXIF_PREFIX))
            .collect();
    }
    if bytes.starts_with(b"\x89PNG\r\n\x1a\n") {
        return png_chunks(bytes)
            .into_iter()
            .filter(|(kind, _)| kind == b"eXIf")
            .map(|(_, data)| data.strip_prefix(EXIF_PREFIX).unwrap_or(data))
            .collect();
    }
    if bytes.len() >= 12 && &bytes[..4] == b"RIFF" && &bytes[8..12] == b"WEBP" {
        return riff_chunks(bytes)
            .into_iter()
            .filter(|(kind, _)| kind == b"EXIF")
            .map(|(_, data)| data.strip_prefix(EXIF_PREFIX).unwrap_or(data))
            .collect();
    }
    if matches!(mime_type, "image/heic" | "image/heif" | "image/avif") {
        return find(bytes, EXIF_PREFIX, 0)
            .map(|at| &bytes[at + EXIF_PREFIX.len()..])
            .filter(|tiff| is_tiff(tiff))
            .into_iter()
            .collect();
    }

    Vec::new()
}

fn iim_blocks(bytes: &[u8]) -> Vec<&[u8]> {
    if !bytes.starts_with(&[0xFF, 0xD8]) {
        return Vec::new();
    }

    jpeg_segments(bytes)
        .into_iter()
        .filter(|(marker, _)| *marker == 0xED)
        .filter_map(|(_, payload)| payload.strip_prefix(PHOTOSHOP_PREFIX))
        .flat_map(photoshop_iptc)
        .collect()
}

fn is_tiff(bytes: &[u8]) -> bool {
    bytes.starts_with(b"II*\0") || bytes.starts_with(b"MM\0*")
}

fn be16(bytes: &[u8], at: usize) -> Option<u16> {
    let b = bytes.get(at..at.checked_add(2)?)?;
    Some(u16::from_be_bytes([b[0], b[1]]))
}

fn be32(bytes: &[u8], at: usize) -> Option<u32> {
    let b = bytes.get(at..at.checked_add(4)?)?;
    Some(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
}

fn le32(bytes: &[u8], at: usize) -> Option<u32> {
    let b = bytes.get(at..at.checked_add(4)?)?;
    Some(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

fn jpeg_segments(bytes: &[u8]) -> Vec<(u8, &[u8])> {
    let mut out = Vec::new();
    let mut at = 2usize;

    while out.len() < MAX_SEGMENTS {
        if bytes.get(at) != Some(&0xFF) {
            break;
        }
        while bytes.get(at + 1) == Some(&0xFF) {
            at += 1;
        }
        let Some(&marker) = bytes.get(at + 1) else {
            break;
        };
        if marker == 0xD9 || marker == 0xDA {
            break;
        }
        if marker == 0x01 || (0xD0..=0xD8).contains(&marker) {
            at += 2;
            continue;
        }
        let Some(length) = be16(bytes, at + 2) else {
            break;
        };
        let length = usize::from(length);
        if length < 2 {
            break;
        }
        let Some(payload) = bytes.get(at + 4..at + 2 + length) else {
            break;
        };
        out.push((marker, payload));
        at += 2 + length;
    }

    out
}

fn png_chunks(bytes: &[u8]) -> Vec<([u8; 4], &[u8])> {
    let mut out = Vec::new();
    let mut at = 8usize;

    while out.len() < MAX_SEGMENTS {
        let Some(length) = be32(bytes, at) else {
            break;
        };
        let Some(kind) = bytes.get(at + 4..at + 8) else {
            break;
        };
        let kind = [kind[0], kind[1], kind[2], kind[3]];
        let start = at + 8;
        let Some(end) = start.checked_add(length as usize) else {
            break;
        };
        let Some(data) = bytes.get(start..end) else {
            break;
        };
        out.push((kind, data));
        if &kind == b"IEND" {
            break;
        }
        let Some(next) = end.checked_add(4) else {
            break;
        };
        at = next;
    }

    out
}

fn riff_chunks(bytes: &[u8]) -> Vec<([u8; 4], &[u8])> {
    let mut out = Vec::new();
    let mut at = 12usize;

    while out.len() < MAX_SEGMENTS {
        let Some(kind) = bytes.get(at..at + 4) else {
            break;
        };
        let kind = [kind[0], kind[1], kind[2], kind[3]];
        let Some(length) = le32(bytes, at + 4) else {
            break;
        };
        let start = at + 8;
        let Some(end) = start.checked_add(length as usize) else {
            break;
        };
        let Some(data) = bytes.get(start..end) else {
            break;
        };
        out.push((kind, data));
        let Some(next) = end.checked_add(length as usize & 1) else {
            break;
        };
        at = next;
    }

    out
}

fn photoshop_iptc(resources: &[u8]) -> Vec<&[u8]> {
    let mut out = Vec::new();
    let mut at = 0usize;

    while out.len() < MAX_SEGMENTS {
        if resources.get(at..at + 4) != Some(b"8BIM".as_slice()) {
            break;
        }
        let Some(id) = be16(resources, at + 4) else {
            break;
        };
        let Some(&name_len) = resources.get(at + 6) else {
            break;
        };
        let mut name_total = 1 + usize::from(name_len);
        if name_total % 2 == 1 {
            name_total += 1;
        }
        let size_at = at + 6 + name_total;
        let Some(size) = be32(resources, size_at) else {
            break;
        };
        let start = size_at + 4;
        let Some(end) = start.checked_add(size as usize) else {
            break;
        };
        let Some(data) = resources.get(start..end) else {
            break;
        };
        if id == 0x0404 {
            out.push(data);
        }
        at = end + (size as usize & 1);
    }

    out
}

fn scan_iim(records: &[u8], found: &mut Found) {
    let mut at = 0usize;

    while let Some(&tag) = records.get(at) {
        if tag != 0x1C {
            break;
        }
        let (Some(&record), Some(&dataset), Some(raw_length)) = (
            records.get(at + 1),
            records.get(at + 2),
            be16(records, at + 3),
        ) else {
            break;
        };
        let mut start = at + 5;
        let length = if raw_length & 0x8000 != 0 {
            let width = usize::from(raw_length & 0x7FFF);
            if width == 0 || width > 4 {
                break;
            }
            let Some(digits) = records.get(start..start + width) else {
                break;
            };
            start += width;
            digits
                .iter()
                .fold(0usize, |acc, b| (acc << 8) | usize::from(*b))
        } else {
            usize::from(raw_length)
        };
        let Some(end) = start.checked_add(length) else {
            break;
        };
        let Some(data) = records.get(start..end) else {
            break;
        };
        if record == 2 && has_text(data) {
            if let Some((_, field)) = IIM_FIELDS.iter().find(|(id, _)| *id == dataset) {
                found.fields.insert(*field);
            }
        }
        at = end;
    }
}

fn has_text(data: &[u8]) -> bool {
    data.iter().any(|b| *b != 0 && !b.is_ascii_whitespace())
}

struct Tiff<'a> {
    bytes: &'a [u8],
    little: bool,
}

impl Tiff<'_> {
    fn u16(&self, at: usize) -> Option<u16> {
        let b = self.bytes.get(at..at.checked_add(2)?)?;
        Some(if self.little {
            u16::from_le_bytes([b[0], b[1]])
        } else {
            u16::from_be_bytes([b[0], b[1]])
        })
    }

    fn u32(&self, at: usize) -> Option<u32> {
        let b = self.bytes.get(at..at.checked_add(4)?)?;
        Some(if self.little {
            u32::from_le_bytes([b[0], b[1], b[2], b[3]])
        } else {
            u32::from_be_bytes([b[0], b[1], b[2], b[3]])
        })
    }

    fn entries(&self, offset: usize) -> Vec<(u16, u16, u32, usize)> {
        let Some(count) = self.u16(offset) else {
            return Vec::new();
        };
        let count = usize::from(count).min(MAX_IFD_ENTRIES);
        let mut out = Vec::with_capacity(count);

        for index in 0..count {
            let entry = offset.saturating_add(2 + index * 12);
            let (Some(tag), Some(kind), Some(n)) = (
                self.u16(entry),
                self.u16(entry.saturating_add(2)),
                self.u32(entry.saturating_add(4)),
            ) else {
                break;
            };
            out.push((tag, kind, n, entry));
        }

        out
    }

    fn value(&self, kind: u16, count: u32, entry: usize) -> Option<&[u8]> {
        let unit: u64 = match kind {
            1 | 2 | 6 | 7 => 1,
            3 | 8 => 2,
            4 | 9 | 11 | 13 => 4,
            5 | 10 | 12 => 8,
            _ => return None,
        };
        let total = usize::try_from(unit.checked_mul(u64::from(count))?).ok()?;
        if total <= 4 {
            let start = entry.saturating_add(8);
            return self.bytes.get(start..start.checked_add(total)?);
        }
        let offset = self.u32(entry.saturating_add(8))? as usize;
        self.bytes.get(offset..offset.checked_add(total)?)
    }
}

fn scan_tiff(bytes: &[u8], found: &mut Found) {
    if !is_tiff(bytes) {
        return;
    }
    let tiff = Tiff {
        bytes,
        little: bytes[0] == b'I',
    };
    let Some(ifd0) = tiff.u32(4) else {
        return;
    };
    let ifd0 = ifd0 as usize;
    let mut exif_ifd = None;

    for (tag, kind, count, entry) in tiff.entries(ifd0) {
        if tag == TAG_EXIF_IFD {
            exif_ifd = tiff.u32(entry.saturating_add(8)).map(|v| v as usize);
            continue;
        }
        if tag == TAG_IPTC {
            if let Some(data) = tiff.value(kind, count, entry) {
                scan_iim(data, found);
            }
            continue;
        }
        mark_exif(&tiff, tag, kind, count, entry, found);
    }

    if let Some(offset) = exif_ifd.filter(|o| *o != ifd0) {
        for (tag, kind, count, entry) in tiff.entries(offset) {
            mark_exif(&tiff, tag, kind, count, entry, found);
        }
    }
}

fn mark_exif(tiff: &Tiff<'_>, tag: u16, kind: u16, count: u32, entry: usize, found: &mut Found) {
    let Some((_, field)) = EXIF_FIELDS.iter().find(|(id, _)| *id == tag) else {
        return;
    };
    if !matches!(kind, 1 | 2 | 7) {
        return;
    }
    if tiff.value(kind, count, entry).is_some_and(has_text) {
        found.fields.insert(*field);
    }
}

fn find(haystack: &[u8], needle: &[u8], from: usize) -> Option<usize> {
    if needle.is_empty() || from >= haystack.len() {
        return None;
    }
    haystack[from..]
        .windows(needle.len())
        .position(|w| w == needle)
        .map(|p| p + from)
}

fn xmp_packets(bytes: &[u8]) -> Vec<&[u8]> {
    let mut out = Vec::new();
    let mut from = 0usize;

    while out.len() < MAX_XMP_PACKETS {
        let Some(start) = find(bytes, XMP_OPEN, from) else {
            break;
        };
        let Some(close) = find(bytes, XMP_CLOSE, start + XMP_OPEN.len()) else {
            break;
        };
        let end = close + XMP_CLOSE.len();
        out.push(&bytes[start..end]);
        from = end;
    }

    out
}

fn xmp_field(name: &str) -> Option<Field> {
    XMP_FIELDS
        .iter()
        .find(|(qualified, _)| *qualified == name)
        .map(|(_, field)| *field)
}

fn ignored_attribute(name: &str) -> bool {
    name == "xmlns" || name.starts_with("xmlns:") || IGNORED_ATTRIBUTES.contains(&name)
}

enum Token<'a> {
    Open {
        name: &'a str,
        attributes: Vec<(&'a str, &'a str)>,
        empty: bool,
    },
    Close(&'a str),
    Text(&'a str),
}

struct Tokens<'a> {
    text: &'a str,
    at: usize,
}

impl<'a> Tokens<'a> {
    fn new(text: &'a str) -> Self {
        Self { text, at: 0 }
    }

    fn rest(&self) -> &'a str {
        self.text.get(self.at..).unwrap_or("")
    }

    fn skip_past(&mut self, marker: &str) -> Option<()> {
        let offset = self.rest().find(marker)?;
        self.at += offset + marker.len();
        Some(())
    }

    fn open_tag(&mut self) -> Option<Token<'a>> {
        let text = self.text;
        let bytes = text.as_bytes();
        let mut at = self.at + 1;
        let name_start = at;
        while at < bytes.len()
            && !bytes[at].is_ascii_whitespace()
            && bytes[at] != b'/'
            && bytes[at] != b'>'
        {
            at += 1;
        }
        let name = text.get(name_start..at)?;
        let mut attributes = Vec::new();

        loop {
            while at < bytes.len() && bytes[at].is_ascii_whitespace() {
                at += 1;
            }
            match *bytes.get(at)? {
                b'>' => {
                    self.at = at + 1;
                    return Some(Token::Open {
                        name,
                        attributes,
                        empty: false,
                    });
                }
                b'/' => {
                    if bytes.get(at + 1) != Some(&b'>') {
                        return None;
                    }
                    self.at = at + 2;
                    return Some(Token::Open {
                        name,
                        attributes,
                        empty: true,
                    });
                }
                _ => {}
            }
            let key_start = at;
            while at < bytes.len()
                && bytes[at] != b'='
                && !bytes[at].is_ascii_whitespace()
                && bytes[at] != b'>'
                && bytes[at] != b'/'
            {
                at += 1;
            }
            let key = text.get(key_start..at)?;
            while at < bytes.len() && bytes[at].is_ascii_whitespace() {
                at += 1;
            }
            if bytes.get(at) != Some(&b'=') {
                return None;
            }
            at += 1;
            while at < bytes.len() && bytes[at].is_ascii_whitespace() {
                at += 1;
            }
            let quote = *bytes.get(at)?;
            if quote != b'"' && quote != b'\'' {
                return None;
            }
            at += 1;
            let value_start = at;
            while at < bytes.len() && bytes[at] != quote {
                at += 1;
            }
            let value = text.get(value_start..at)?;
            at += 1;
            attributes.push((key, value));
        }
    }
}

impl<'a> Iterator for Tokens<'a> {
    type Item = Token<'a>;

    fn next(&mut self) -> Option<Token<'a>> {
        loop {
            let rest = self.rest();
            if rest.is_empty() {
                return None;
            }
            if !rest.starts_with('<') {
                let end = rest.find('<').unwrap_or(rest.len());
                self.at += end;
                return Some(Token::Text(&rest[..end]));
            }
            if rest.starts_with("<?") {
                self.skip_past("?>")?;
                continue;
            }
            if rest.starts_with("<!--") {
                self.skip_past("-->")?;
                continue;
            }
            if let Some(body) = rest.strip_prefix("<![CDATA[") {
                let end = body.find("]]>")?;
                self.at += "<![CDATA[".len() + end + "]]>".len();
                return Some(Token::Text(&body[..end]));
            }
            if rest.starts_with("<!") {
                self.skip_past(">")?;
                continue;
            }
            if let Some(body) = rest.strip_prefix("</") {
                let end = body.find('>')?;
                self.at += 2 + end + 1;
                return Some(Token::Close(body[..end].trim()));
            }
            return self.open_tag();
        }
    }
}

fn scan_xmp(packet: &str, found: &mut Found) {
    let mut stack: Vec<(&str, Option<Field>)> = Vec::new();

    for token in Tokens::new(packet) {
        match token {
            Token::Open {
                name,
                attributes,
                empty,
            } => {
                let own = xmp_field(name);
                for (key, value) in attributes {
                    if ignored_attribute(key) || value.trim().is_empty() {
                        continue;
                    }
                    if let Some(field) = xmp_field(key) {
                        found.mark(field, value);
                    }
                    if let Some(field) = own {
                        found.mark(field, value);
                    }
                    for field in stack.iter().filter_map(|(_, f)| *f) {
                        found.mark(field, value);
                    }
                }
                if !empty {
                    if stack.len() >= MAX_XMP_DEPTH {
                        return;
                    }
                    stack.push((name, own));
                }
            }
            Token::Close(name) => {
                if let Some(index) = stack.iter().rposition(|(open, _)| *open == name) {
                    stack.truncate(index);
                }
            }
            Token::Text(text) => {
                if text.trim().is_empty() {
                    continue;
                }
                for field in stack.iter().filter_map(|(_, f)| *f) {
                    found.mark(field, text);
                }
            }
        }
    }
}

fn unescape(value: &str) -> String {
    value
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
        .replace("&amp;", "&")
}

fn bounded(value: &str) -> String {
    value.chars().take(MAX_VALUE_CHARS).collect()
}

fn last_segment(value: &str) -> String {
    let trimmed = value.trim().trim_end_matches('/');
    trimmed.rsplit('/').next().unwrap_or(trimmed).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn names(meta: &Metadata) -> Vec<&str> {
        meta.fields.iter().map(String::as_str).collect()
    }

    fn jpeg_with(segments: &[(u8, Vec<u8>)]) -> Vec<u8> {
        let mut out = vec![0xFF, 0xD8];
        for (marker, payload) in segments {
            out.extend_from_slice(&[0xFF, *marker]);
            out.extend_from_slice(&((payload.len() + 2) as u16).to_be_bytes());
            out.extend_from_slice(payload);
        }
        out.extend_from_slice(&[0xFF, 0xDA, 0x00, 0x02, 0xFF, 0xD9]);
        out
    }

    fn iim(records: &[(u8, &str)]) -> Vec<u8> {
        let mut out = Vec::new();
        for (dataset, value) in records {
            out.extend_from_slice(&[0x1C, 2, *dataset]);
            out.extend_from_slice(&(value.len() as u16).to_be_bytes());
            out.extend_from_slice(value.as_bytes());
        }
        out
    }

    fn app13(iim: &[u8]) -> Vec<u8> {
        let mut out = PHOTOSHOP_PREFIX.to_vec();
        out.extend_from_slice(b"8BIM");
        out.extend_from_slice(&0x0404u16.to_be_bytes());
        out.extend_from_slice(&[0, 0]);
        out.extend_from_slice(&(iim.len() as u32).to_be_bytes());
        out.extend_from_slice(iim);
        if iim.len() % 2 == 1 {
            out.push(0);
        }
        out
    }

    fn tiff_le(ifd0: &[(u16, &str)], exif: &[(u16, &str)]) -> Vec<u8> {
        let ifd0_len = ifd0.len() + usize::from(!exif.is_empty());
        let ifd0_size = 2 + ifd0_len * 12 + 4;
        let exif_offset = 8 + ifd0_size;
        let exif_size = if exif.is_empty() {
            0
        } else {
            2 + exif.len() * 12 + 4
        };
        let mut data_offset = exif_offset + exif_size;
        let mut data = Vec::new();

        let ifd = |entries: Vec<(u16, u16, u32, Vec<u8>)>,
                   data: &mut Vec<u8>,
                   data_offset: &mut usize| {
            let mut out = Vec::new();
            out.extend_from_slice(&(entries.len() as u16).to_le_bytes());
            for (tag, kind, count, payload) in entries {
                out.extend_from_slice(&tag.to_le_bytes());
                out.extend_from_slice(&kind.to_le_bytes());
                out.extend_from_slice(&count.to_le_bytes());
                if payload.len() <= 4 {
                    let mut inline = payload.clone();
                    inline.resize(4, 0);
                    out.extend_from_slice(&inline);
                } else {
                    out.extend_from_slice(&(*data_offset as u32).to_le_bytes());
                    *data_offset += payload.len();
                    data.extend_from_slice(&payload);
                }
            }
            out.extend_from_slice(&0u32.to_le_bytes());
            out
        };

        let ascii = |entries: &[(u16, &str)]| -> Vec<(u16, u16, u32, Vec<u8>)> {
            entries
                .iter()
                .map(|(tag, value)| {
                    let mut bytes = value.as_bytes().to_vec();
                    bytes.push(0);
                    (*tag, 2u16, bytes.len() as u32, bytes)
                })
                .collect()
        };

        let mut first = ascii(ifd0);
        if !exif.is_empty() {
            first.push((
                TAG_EXIF_IFD,
                4,
                1,
                (exif_offset as u32).to_le_bytes().to_vec(),
            ));
        }
        let first = ifd(first, &mut data, &mut data_offset);
        let second = if exif.is_empty() {
            Vec::new()
        } else {
            ifd(ascii(exif), &mut data, &mut data_offset)
        };

        let mut out = b"II*\0".to_vec();
        out.extend_from_slice(&8u32.to_le_bytes());
        out.extend_from_slice(&first);
        out.extend_from_slice(&second);
        out.extend_from_slice(&data);
        out
    }

    const XMP: &str = r#"<?xpacket begin="" id="W5M0MpCehiHzreSzNTczkc9d"?>
<x:xmpmeta xmlns:x="adobe:ns:meta/" x:xmptk="test">
 <rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#">
  <rdf:Description rdf:about=""
    xmlns:dc="http://purl.org/dc/elements/1.1/"
    xmlns:photoshop="http://ns.adobe.com/photoshop/1.0/"
    xmlns:Iptc4xmpExt="http://iptc.org/std/Iptc4xmpExt/2008-02-29/"
    xmlns:plus="http://ns.useplus.org/ldf/xmp/1.0/"
    photoshop:Credit="Agency &amp; Co"
    Iptc4xmpExt:DigitalSourceType="http://cv.iptc.org/newscodes/digitalsourcetype/trainedAlgorithmicMedia"
    photoshop:Source="">
   <dc:creator><rdf:Seq><rdf:li>Jane Doe</rdf:li></rdf:Seq></dc:creator>
   <dc:rights><rdf:Alt><rdf:li xml:lang="x-default">  </rdf:li></rdf:Alt></dc:rights>
   <dc:description><rdf:Alt><rdf:li xml:lang="x-default"><![CDATA[A caption]]></rdf:li></rdf:Alt></dc:description>
   <Iptc4xmpExt:AISystemUsed>Image Model &lt;v2&gt;</Iptc4xmpExt:AISystemUsed>
   <Iptc4xmpExt:LocationCreated><rdf:Bag><rdf:li Iptc4xmpExt:City="Paris"/></rdf:Bag></Iptc4xmpExt:LocationCreated>
   <Iptc4xmpExt:LocationShown><rdf:Bag><rdf:li rdf:parseType="Resource"/></rdf:Bag></Iptc4xmpExt:LocationShown>
   <plus:Licensor><rdf:Seq><rdf:li plus:LicensorURL="https://example.com/license"/></rdf:Seq></plus:Licensor>
   <plus:DataMining rdf:resource="http://ns.useplus.org/ldf/vocab/DMI-PROHIBITED"/>
   <!-- <dc:title>commented out</dc:title> -->
  </rdf:Description>
 </rdf:RDF>
</x:xmpmeta>
<?xpacket end="w"?>"#;

    #[test]
    fn the_xmp_scanner_reads_elements_and_attributes() {
        let meta = extract(XMP.as_bytes(), "image/png");

        assert_eq!(
            names(&meta),
            vec![
                "AISystemUsed",
                "CaptionDescription",
                "Creator",
                "CreditLine",
                "DataMining",
                "DigitalSourceType",
                "LicensorURL",
                "LocationCreated",
            ]
        );
        assert_eq!(meta.four_cs_score, 75);
        assert_eq!(
            meta.digital_source_type.as_deref(),
            Some("trainedAlgorithmicMedia")
        );
        assert_eq!(meta.ai_system_used.as_deref(), Some("Image Model <v2>"));
    }

    #[test]
    fn an_xmp_packet_is_found_inside_other_bytes() {
        let mut bytes = b"\x89PNG\r\n\x1a\n junk iTXt XML:com.adobe.xmp\0\0\0\0\0".to_vec();
        bytes.extend_from_slice(XMP.as_bytes());
        bytes.extend_from_slice(b"\0\0IEND");

        let meta = extract(&bytes, "image/png");

        assert!(meta.fields.contains(&"Creator".to_string()));
    }

    #[test]
    fn a_truncated_xmp_packet_yields_nothing_and_does_not_panic() {
        let cut = &XMP[..XMP.len() / 2];

        assert_eq!(extract(cut.as_bytes(), "image/jpeg"), Metadata::default());
        for end in 0..XMP.len() {
            if let Some(prefix) = XMP.get(..end) {
                let mut found = Found::default();
                scan_xmp(prefix, &mut found);
            }
        }
    }

    #[test]
    fn an_element_form_digital_source_type_is_reduced_to_its_code() {
        let xmp = r#"<x:xmpmeta><rdf:Description><Iptc4xmpExt:DigitalSourceType>http://cv.iptc.org/newscodes/digitalsourcetype/compositeWithTrainedAlgorithmicMedia</Iptc4xmpExt:DigitalSourceType></rdf:Description></x:xmpmeta>"#;

        let meta = extract(xmp.as_bytes(), "image/webp");

        assert_eq!(
            meta.digital_source_type.as_deref(),
            Some("compositeWithTrainedAlgorithmicMedia")
        );
        assert_eq!(names(&meta), vec!["DigitalSourceType"]);
        assert_eq!(meta.four_cs_score, 0);
    }

    #[test]
    fn iim_records_in_a_jpeg_app13_segment_are_mapped() {
        let records = iim(&[
            (80, "Jane Doe"),
            (116, "(c) 2026 Jane Doe"),
            (120, "A caption"),
            (110, "Agency"),
            (25, "news"),
            (55, "20260101"),
            (115, ""),
            (5, "Headline"),
            (15, "Category"),
        ]);
        let jpeg = jpeg_with(&[(0xED, app13(&records))]);

        let meta = extract(&jpeg, "image/jpeg");

        assert_eq!(
            names(&meta),
            vec![
                "CaptionDescription",
                "Copyright",
                "Creator",
                "CreditLine",
                "DateCreated",
                "Keywords",
                "ObjectName",
            ]
        );
        assert_eq!(meta.four_cs_score, 100);
    }

    #[test]
    fn exif_ifd0_and_the_exif_sub_ifd_are_mapped() {
        let tiff = tiff_le(
            &[
                (0x013B, "Jane Doe"),
                (0x8298, " "),
                (0x010E, "A caption that is long"),
            ],
            &[(0x9003, "2026:01:01 10:00:00")],
        );
        let mut payload = EXIF_PREFIX.to_vec();
        payload.extend_from_slice(&tiff);
        let jpeg = jpeg_with(&[(0xE1, payload)]);

        let meta = extract(&jpeg, "image/jpeg");

        assert_eq!(
            names(&meta),
            vec!["CaptionDescription", "Creator", "DateCreated"]
        );
        assert_eq!(meta.four_cs_score, 50);
    }

    #[test]
    fn a_bare_tiff_is_read_as_exif() {
        let tiff = tiff_le(&[(0x8298, "Copyright holder")], &[]);

        let meta = extract(&tiff, "image/tiff");

        assert_eq!(names(&meta), vec!["Copyright"]);
    }

    #[test]
    fn hostile_lengths_are_refused_without_panicking() {
        let mut huge = PHOTOSHOP_PREFIX.to_vec();
        huge.extend_from_slice(b"8BIM\x04\x04\x00\x00\xFF\xFF\xFF\xFF");
        let jpeg = jpeg_with(&[(0xED, huge)]);
        assert_eq!(extract(&jpeg, "image/jpeg"), Metadata::default());

        let mut iim_huge = vec![0x1C, 2, 80, 0x80, 0x04, 0xFF, 0xFF, 0xFF, 0xFF];
        iim_huge.extend_from_slice(b"x");
        let jpeg = jpeg_with(&[(0xED, app13(&iim_huge))]);
        assert_eq!(extract(&jpeg, "image/jpeg"), Metadata::default());

        let mut tiff = b"II*\0".to_vec();
        tiff.extend_from_slice(&8u32.to_le_bytes());
        tiff.extend_from_slice(&0xFFFFu16.to_le_bytes());
        tiff.extend_from_slice(&0x013Bu16.to_le_bytes());
        tiff.extend_from_slice(&2u16.to_le_bytes());
        tiff.extend_from_slice(&u32::MAX.to_le_bytes());
        tiff.extend_from_slice(&u32::MAX.to_le_bytes());
        assert_eq!(extract(&tiff, "image/tiff"), Metadata::default());

        let cases: [&[u8]; 8] = [
            &[0xFF, 0xD8, 0xFF],
            &[0xFF, 0xD8, 0xFF, 0xE1, 0x00],
            &[0xFF, 0xD8, 0xFF, 0xE1, 0x00, 0x01],
            b"RIFF\0\0\0\0WEBPEXIF\xFF\xFF\xFF\xFF",
            b"\x89PNG\r\n\x1a\n\xFF\xFF\xFF\xFFeXIf",
            b"II*\0\xFF\xFF\xFF\xFF",
            b"<x:xmpmeta",
            b"<x:xmpmeta></x:xmpmeta>",
        ];
        for bytes in cases {
            assert_eq!(extract(bytes, "image/jpeg"), Metadata::default());
        }
    }

    #[test]
    fn a_png_exif_chunk_is_read() {
        let tiff = tiff_le(&[(0x013B, "Jane Doe")], &[]);
        let mut png = b"\x89PNG\r\n\x1a\n".to_vec();
        png.extend_from_slice(&(tiff.len() as u32).to_be_bytes());
        png.extend_from_slice(b"eXIf");
        png.extend_from_slice(&tiff);
        png.extend_from_slice(&[0, 0, 0, 0]);
        png.extend_from_slice(&[0, 0, 0, 0]);
        png.extend_from_slice(b"IEND");
        png.extend_from_slice(&[0, 0, 0, 0]);

        assert_eq!(names(&extract(&png, "image/png")), vec!["Creator"]);
    }

    #[test]
    fn a_webp_exif_chunk_is_read() {
        let tiff = tiff_le(&[(0x010E, "A caption")], &[]);
        let mut body = b"WEBP".to_vec();
        body.extend_from_slice(b"EXIF");
        body.extend_from_slice(&(tiff.len() as u32).to_le_bytes());
        body.extend_from_slice(&tiff);
        if tiff.len() % 2 == 1 {
            body.push(0);
        }
        let mut webp = b"RIFF".to_vec();
        webp.extend_from_slice(&(body.len() as u32).to_le_bytes());
        webp.extend_from_slice(&body);

        assert_eq!(
            names(&extract(&webp, "image/webp")),
            vec!["CaptionDescription"]
        );
    }

    #[test]
    fn metadata_applies_only_to_images() {
        assert!(applies_to("image/jpeg"));
        assert!(applies_to("image/svg+xml"));
        assert!(!applies_to("video/mp4"));
        assert!(!applies_to("application/pdf"));
    }

    #[test]
    fn the_last_path_segment_is_the_code() {
        assert_eq!(
            last_segment("http://cv.iptc.org/newscodes/digitalsourcetype/digitalCapture/"),
            "digitalCapture"
        );
        assert_eq!(
            last_segment("trainedAlgorithmicMedia"),
            "trainedAlgorithmicMedia"
        );
    }

    #[test]
    fn field_names_sort_in_the_order_they_are_reported() {
        let mut names: Vec<&str> = XMP_FIELDS.iter().map(|(_, f)| f.name()).collect();
        names.sort_unstable();
        names.dedup();
        let mut fields: Vec<Field> = XMP_FIELDS.iter().map(|(_, f)| *f).collect();
        fields.sort_unstable();
        fields.dedup();

        assert_eq!(fields.iter().map(|f| f.name()).collect::<Vec<_>>(), names);
    }
}

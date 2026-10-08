use std::io::Cursor;

use image::{ImageFormat, ImageReader};

use crate::error::Error;

const SUPPORTED: &[(&str, &str)] = &[
    ("image/jpeg", "jpeg"),
    ("image/png", "png"),
    ("image/webp", "webp"),
    ("image/gif", "gif"),
    ("image/avif", "avif"),
    ("image/heic", "heic"),
    ("image/heif", "heif"),
    ("image/tiff", "tiff"),
    ("image/svg+xml", "svg"),
    ("video/mp4", "mp4"),
    ("video/quicktime", "mov"),
    ("audio/mpeg", "mp3"),
    ("audio/wav", "wav"),
    ("application/pdf", "pdf"),
    ("application/c2pa", "c2pa"),
];

pub fn base_type(mime: &str) -> &str {
    mime.split(';').next().unwrap_or(mime).trim()
}

pub fn format_for(mime: &str) -> Option<&'static str> {
    let base = base_type(mime);

    SUPPORTED
        .iter()
        .find(|(candidate, _)| *candidate == base)
        .map(|(_, format)| *format)
}

pub fn require_format(mime: &str) -> Result<&'static str, Error> {
    format_for(mime).ok_or_else(|| Error::UnsupportedMediaType(mime.to_string()))
}

pub fn mime_from_extension(name: &str) -> &'static str {
    let ext = name.rsplit('.').next().unwrap_or("").to_lowercase();

    match ext.as_str() {
        "jpg" | "jpeg" => "image/jpeg",
        "png" => "image/png",
        "webp" => "image/webp",
        "gif" => "image/gif",
        "avif" => "image/avif",
        "heic" => "image/heic",
        "heif" => "image/heif",
        "tif" | "tiff" => "image/tiff",
        "svg" => "image/svg+xml",
        "mp4" | "m4v" => "video/mp4",
        "mov" => "video/quicktime",
        "mp3" => "audio/mpeg",
        "wav" => "audio/wav",
        "pdf" => "application/pdf",
        "c2pa" => "application/c2pa",
        _ => "application/octet-stream",
    }
}

pub fn dimensions(bytes: &[u8], max_pixels: u64) -> Result<Option<(u32, u32)>, Error> {
    let Ok(reader) = ImageReader::new(Cursor::new(bytes)).with_guessed_format() else {
        return Ok(None);
    };
    let Some((width, height)) = header_dimensions(reader, bytes) else {
        return Ok(None);
    };

    if u64::from(width) * u64::from(height) > max_pixels {
        return Err(Error::LimitExceeded(format!(
            "{width}x{height} exceeds the {max_pixels} pixel limit"
        )));
    }

    Ok(Some((width, height)))
}

fn header_dimensions(reader: ImageReader<Cursor<&[u8]>>, bytes: &[u8]) -> Option<(u32, u32)> {
    if reader.format() == Some(ImageFormat::Avif) {
        return avif_dimensions(bytes);
    }

    reader.into_dimensions().ok()
}

#[cfg(feature = "avif")]
fn avif_dimensions(bytes: &[u8]) -> Option<(u32, u32)> {
    crate::av1::coded_size(bytes).map(|size| (size.width, size.height))
}

#[cfg(not(feature = "avif"))]
fn avif_dimensions(_: &[u8]) -> Option<(u32, u32)> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    const PIXEL_CAP: u64 = 100_000_000;

    fn crc32(bytes: &[u8]) -> u32 {
        let mut crc = 0xffff_ffff_u32;
        for byte in bytes {
            crc ^= u32::from(*byte);
            for _ in 0..8 {
                let mask = (crc & 1).wrapping_neg();
                crc = (crc >> 1) ^ (0xedb8_8320 & mask);
            }
        }

        !crc
    }

    fn chunk(kind: &[u8; 4], data: &[u8]) -> Vec<u8> {
        let mut body = Vec::from(*kind);
        body.extend_from_slice(data);

        let mut out = Vec::new();
        out.extend_from_slice(&(data.len() as u32).to_be_bytes());
        out.extend_from_slice(&body);
        out.extend_from_slice(&crc32(&body).to_be_bytes());

        out
    }

    fn png(width: u32, height: u32, pixels: &[u8]) -> Vec<u8> {
        let mut header = Vec::new();
        header.extend_from_slice(&width.to_be_bytes());
        header.extend_from_slice(&height.to_be_bytes());
        header.extend_from_slice(&[8, 6, 0, 0, 0]);

        let mut out = Vec::from([0x89, b'P', b'N', b'G', 0x0d, 0x0a, 0x1a, 0x0a]);
        out.extend_from_slice(&chunk(b"IHDR", &header));
        out.extend_from_slice(&chunk(b"IDAT", pixels));
        out.extend_from_slice(&chunk(b"IEND", &[]));

        out
    }

    fn png_header(width: u32, height: u32) -> Vec<u8> {
        png(width, height, &[])
    }

    #[test]
    fn refuses_media_types_no_parser_handles() {
        assert!(require_format("application/zip").is_err());
        assert!(require_format("").is_err());
        assert!(require_format("image/bmp").is_err());
    }

    #[test]
    fn accepts_the_media_types_the_reader_handles() {
        assert_eq!(require_format("image/jpeg").unwrap(), "jpeg");
        assert_eq!(require_format("application/pdf").unwrap(), "pdf");
        assert_eq!(require_format("video/mp4").unwrap(), "mp4");
        assert_eq!(require_format("image/gif").unwrap(), "gif");
    }

    #[test]
    fn a_charset_parameter_does_not_hide_the_media_type() {
        assert_eq!(require_format("image/png; charset=binary").unwrap(), "png");
        assert_eq!(require_format("  image/png  ").unwrap(), "png");
    }

    #[test]
    fn guesses_a_type_from_the_filename_when_the_caller_sends_none() {
        assert_eq!(mime_from_extension("photo.JPG"), "image/jpeg");
        assert_eq!(mime_from_extension("clip.mp4"), "video/mp4");
        assert_eq!(mime_from_extension("scan.TIFF"), "image/tiff");
    }

    #[test]
    fn a_name_without_a_known_extension_stays_opaque() {
        assert_eq!(mime_from_extension("notes"), "application/octet-stream");
        assert_eq!(mime_from_extension(""), "application/octet-stream");
        assert_eq!(
            mime_from_extension("archive.zip"),
            "application/octet-stream"
        );
    }

    #[test]
    fn every_guessed_type_is_a_type_the_reader_accepts() {
        for name in [
            "a.jpg", "a.png", "a.webp", "a.gif", "a.avif", "a.heic", "a.tif", "a.svg", "a.mp4",
            "a.mov", "a.mp3", "a.wav", "a.pdf", "a.c2pa",
        ] {
            let mime = mime_from_extension(name);

            assert!(format_for(mime).is_some(), "{name} guessed {mime}");
        }
    }

    #[test]
    fn dimensions_come_from_the_header_alone() {
        let png = png_header(640, 480);

        assert_eq!(dimensions(&png, PIXEL_CAP).unwrap(), Some((640, 480)));
    }

    #[test]
    fn a_declared_size_beyond_the_cap_is_refused_rather_than_reported_as_unknown() {
        let png = png_header(60_000, 60_000);

        let refused = dimensions(&png, PIXEL_CAP);

        assert!(refused.is_err());
        assert_eq!(refused.unwrap_err().code(), "limit_exceeded");
        assert_eq!(dimensions(&png, u64::MAX).unwrap(), Some((60_000, 60_000)));
    }

    #[test]
    fn a_size_exactly_at_the_cap_is_accepted() {
        let png = png_header(10_000, 10_000);

        assert_eq!(
            dimensions(&png, 100_000_000).unwrap(),
            Some((10_000, 10_000))
        );
        assert!(dimensions(&png, 99_999_999).is_err());
    }

    #[test]
    fn unreadable_bytes_report_no_dimensions_rather_than_failing() {
        assert_eq!(dimensions(b"", PIXEL_CAP).unwrap(), None);
        assert_eq!(dimensions(b"not an image at all", PIXEL_CAP).unwrap(), None);
        assert_eq!(
            dimensions(&png_header(1, 1)[..12], PIXEL_CAP).unwrap(),
            None
        );
    }

    #[test]
    fn pixel_data_is_never_decoded_to_read_a_size() {
        let declared = png(4_000, 4_000, b"this is not deflate data");

        assert_eq!(
            dimensions(&declared, PIXEL_CAP).unwrap(),
            Some((4_000, 4_000))
        );
    }

    #[test]
    fn a_decompression_bomb_is_cheap_because_the_pixels_are_never_inflated() {
        let bomb = png(4_000, 4_000, &[0u8; 64]);

        assert_eq!(dimensions(&bomb, PIXEL_CAP).unwrap(), Some((4_000, 4_000)));
    }
}

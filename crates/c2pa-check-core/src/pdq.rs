use std::io::Cursor;
use std::panic::{catch_unwind, AssertUnwindSafe};

use image::{AnimationDecoder, DynamicImage, ImageDecoder, ImageFormat, ImageReader, Limits};

const SIDE: usize = 64;
const DCT: usize = 16;
const PRESCALE: u32 = 512;
const MAX_DECODE_ALLOC: u64 = 256 * 1024 * 1024;
#[cfg(any(feature = "avif", feature = "heic"))]
const CODEC_BYTES_PER_PIXEL: u64 = 12;
pub const MAX_SIDE: u32 = 8192;
pub const MAX_FRAME_PIXELS: u64 = 50_000_000;
pub const MAX_FRAMES: usize = 300;
pub const MAX_TOTAL_PIXELS: u64 = 500_000_000;
pub const MAX_KEPT_FRAMES: usize = 16;
pub const MIN_QUALITY: u8 = 50;
pub const MATCH_DISTANCE: u32 = 31;
const FRAME_INTERVAL_MS: u64 = 1000;
const FRAME_DEDUPE_DISTANCE: u32 = 2;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pdq {
    pub hash: String,
    pub quality: u8,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Fingerprint {
    pub pdq: Option<Pdq>,
    pub black: Option<String>,
    pub mirrors: Vec<String>,
    pub frames: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Variants {
    primary: Pdq,
    black: Option<String>,
    mirrors: Vec<String>,
}

impl Variants {
    fn into_fingerprint(self, frames: Vec<String>) -> Fingerprint {
        Fingerprint {
            pdq: Some(self.primary),
            black: self.black,
            mirrors: self.mirrors,
            frames,
        }
    }
}

pub fn fingerprint(bytes: &[u8], format: &str, max_pixels: u64) -> Fingerprint {
    catch_unwind(AssertUnwindSafe(|| match format {
        "gif" => animated(bytes, max_pixels),
        "jpeg" => still(decode(bytes, ImageFormat::Jpeg, max_pixels)),
        "png" => still(decode(bytes, ImageFormat::Png, max_pixels)),
        "webp" => still(decode(bytes, ImageFormat::WebP, max_pixels)),
        #[cfg(feature = "avif")]
        "avif" => still(avif(bytes, max_pixels)),
        #[cfg(feature = "heic")]
        "heic" | "heif" => still(heic::decode(bytes, codec_cap(max_pixels))),
        _ => Fingerprint::default(),
    }))
    .unwrap_or_default()
}

fn still(image: Option<DynamicImage>) -> Fingerprint {
    image.map_or_else(Fingerprint::default, |image| {
        variants(image, true).into_fingerprint(Vec::new())
    })
}

fn within(width: u32, height: u32, max_pixels: u64) -> bool {
    width <= MAX_SIDE
        && height <= MAX_SIDE
        && u64::from(width) * u64::from(height) <= max_pixels.min(MAX_FRAME_PIXELS)
}

#[cfg(any(feature = "avif", feature = "heic"))]
fn codec_cap(max_pixels: u64) -> u64 {
    max_pixels.min(MAX_DECODE_ALLOC / CODEC_BYTES_PER_PIXEL)
}

fn limits() -> Limits {
    let mut limits = Limits::default();
    limits.max_image_width = Some(MAX_SIDE);
    limits.max_image_height = Some(MAX_SIDE);
    limits.max_alloc = Some(MAX_DECODE_ALLOC);
    limits
}

fn decode(bytes: &[u8], format: ImageFormat, max_pixels: u64) -> Option<DynamicImage> {
    let mut reader = ImageReader::with_format(Cursor::new(bytes), format);
    reader.limits(limits());
    let decoder = reader.into_decoder().ok()?;
    let (width, height) = decoder.dimensions();
    if !within(width, height, max_pixels) {
        return None;
    }

    DynamicImage::from_decoder(decoder).ok()
}

#[cfg(feature = "avif")]
fn avif(bytes: &[u8], max_pixels: u64) -> Option<DynamicImage> {
    let size = crate::av1::coded_size(bytes)?;
    if !within(size.limit_width, size.limit_height, codec_cap(max_pixels)) {
        return None;
    }

    decode(bytes, ImageFormat::Avif, max_pixels)
}

#[cfg(feature = "heic")]
mod heic {
    use image::{DynamicImage, RgbaImage};
    use libheif_rs::{ColorSpace, HeifContext, LibHeif, RgbChroma, SecurityLimits};

    pub fn decode(bytes: &[u8], max_pixels: u64) -> Option<DynamicImage> {
        let mut context = HeifContext::read_from_bytes(bytes).ok()?;
        let mut limits = SecurityLimits::new();
        limits.set_max_image_size_pixels(max_pixels);
        context.set_security_limits(&limits).ok()?;
        let handle = context.primary_image_handle().ok()?;
        if !super::within(handle.width(), handle.height(), max_pixels) {
            return None;
        }
        let image = LibHeif::new()
            .decode(&handle, ColorSpace::Rgb(RgbChroma::Rgba), None)
            .ok()?;
        let plane = image.planes().interleaved?;
        let (width, height) = (plane.width, plane.height);
        if !super::within(width, height, max_pixels) {
            return None;
        }
        let row = usize::try_from(width).ok()?.checked_mul(4)?;
        let mut pixels = Vec::with_capacity(row.checked_mul(usize::try_from(height).ok()?)?);
        for line in plane.data.chunks(plane.stride.max(1)).take(height as usize) {
            pixels.extend_from_slice(line.get(..row)?);
        }

        RgbaImage::from_raw(width, height, pixels).map(DynamicImage::ImageRgba8)
    }
}

fn animated(bytes: &[u8], max_pixels: u64) -> Fingerprint {
    let Ok(mut decoder) = image::codecs::gif::GifDecoder::new(Cursor::new(bytes)) else {
        return Fingerprint::default();
    };
    let (width, height) = decoder.dimensions();
    if !within(width, height, max_pixels) || decoder.set_limits(limits()).is_err() {
        return Fingerprint::default();
    }
    let canvas = u64::from(width) * u64::from(height);

    let mut lead: Option<Variants> = None;
    let mut fallback: Option<Variants> = None;
    let mut kept: Vec<String> = Vec::new();
    let mut decoded = 0u64;
    let mut clock = 0u64;
    let mut next_due = 0u64;

    for frame in decoder.into_frames().take(MAX_FRAMES) {
        let Ok(frame) = frame else {
            break;
        };
        decoded = decoded.saturating_add(canvas);
        if decoded > MAX_TOTAL_PIXELS {
            break;
        }
        let (numer, denom) = frame.delay().numer_denom_ms();
        let at = clock;
        clock = clock.saturating_add(u64::from(numer) / u64::from(denom.max(1)));
        if at < next_due {
            continue;
        }
        next_due = at.saturating_add(FRAME_INTERVAL_MS);

        let variants = variants(
            DynamicImage::ImageRgba8(frame.into_buffer()),
            lead.is_none(),
        );
        if variants.primary.quality < MIN_QUALITY {
            if lead.is_none() && fallback.is_none() {
                fallback = Some(variants);
            }
            continue;
        }
        let duplicate = kept
            .last()
            .and_then(|last| hamming(last, &variants.primary.hash))
            .is_some_and(|d| d <= FRAME_DEDUPE_DISTANCE);
        if duplicate {
            continue;
        }
        kept.push(variants.primary.hash.clone());
        if lead.is_none() {
            lead = Some(variants);
        }
        if kept.len() == MAX_KEPT_FRAMES {
            break;
        }
    }

    match (lead, fallback) {
        (Some(lead), _) if kept.len() > 1 => lead.into_fingerprint(kept),
        (Some(lead), _) => lead.into_fingerprint(Vec::new()),
        (None, Some(first)) => first.into_fingerprint(Vec::new()),
        (None, None) => Fingerprint::default(),
    }
}

fn variants(image: DynamicImage, full: bool) -> Variants {
    let image = if image.width() > PRESCALE || image.height() > PRESCALE {
        image.thumbnail(PRESCALE, PRESCALE)
    } else {
        image
    };
    let rgba = image.into_rgba8();
    let cols = rgba.width() as usize;
    let rows = rgba.height() as usize;

    if cols == 0 || rows == 0 {
        let zero = "0".repeat(SIDE);
        return Variants {
            primary: Pdq {
                hash: zero.clone(),
                quality: 0,
            },
            black: None,
            mirrors: if full {
                vec![zero.clone(), zero]
            } else {
                Vec::new()
            },
        };
    }

    let mut luma = composite(&rgba, 255.0);
    let (quality, dct) = transform(&mut luma, rows, cols);

    let black = (full && rgba.pixels().any(|p| p[3] < u8::MAX)).then(|| {
        let mut luma = composite(&rgba, 0.0);
        let (_, dct) = transform(&mut luma, rows, cols);
        bits(&dct, |_, _| 1.0)
    });

    Variants {
        primary: Pdq {
            hash: bits(&dct, |_, _| 1.0),
            quality,
        },
        black,
        mirrors: if full {
            vec![
                bits(&dct, |_, b| if b % 2 == 0 { -1.0 } else { 1.0 }),
                bits(&dct, |a, _| if a % 2 == 0 { -1.0 } else { 1.0 }),
            ]
        } else {
            Vec::new()
        },
    }
}

fn composite(rgba: &image::RgbaImage, background: f32) -> Vec<f32> {
    rgba.pixels()
        .map(|p| {
            let luma = 0.299 * f32::from(p[0]) + 0.587 * f32::from(p[1]) + 0.114 * f32::from(p[2]);
            let alpha = f32::from(p[3]) / 255.0;
            luma * alpha + background * (1.0 - alpha)
        })
        .collect()
}

fn bits(dct: &[[f32; DCT]; DCT], sign: impl Fn(usize, usize) -> f32) -> String {
    let mut signed = [[0f32; DCT]; DCT];
    for (a, row) in dct.iter().enumerate() {
        for (b, value) in row.iter().enumerate() {
            signed[a][b] = value * sign(a, b);
        }
    }

    let mut sorted = [0f32; DCT * DCT];
    for (slot, value) in sorted.iter_mut().zip(signed.iter().flatten()) {
        *slot = *value;
    }
    sorted.sort_unstable_by(f32::total_cmp);
    let median = sorted[DCT * DCT / 2 - 1];

    let mut words = [0u16; DCT];
    for (i, row) in signed.iter().enumerate() {
        for (j, value) in row.iter().enumerate() {
            if *value > median {
                words[i] |= 1 << j;
            }
        }
    }

    words.iter().rev().map(|w| format!("{w:04x}")).collect()
}

fn transform(luma: &mut [f32], rows: usize, cols: usize) -> (u8, [[f32; DCT]; DCT]) {
    let mut scratch = vec![0f32; luma.len()];
    let window_rows = window_size(cols);
    let window_cols = window_size(rows);

    for _ in 0..2 {
        for i in 0..rows {
            let start = i * cols;
            box_1d(
                &luma[start..start + cols],
                &mut scratch[start..start + cols],
                1,
                cols,
                window_rows,
            );
        }
        for j in 0..cols {
            box_1d(&scratch[j..], &mut luma[j..], cols, rows, window_cols);
        }
    }

    let mut grid = [[0f32; SIDE]; SIDE];
    for (i, row) in grid.iter_mut().enumerate() {
        let ini = (((i as f64 + 0.5) * rows as f64) / SIDE as f64) as usize;
        let ini = ini.min(rows - 1);
        for (j, cell) in row.iter_mut().enumerate() {
            let inj = (((j as f64 + 0.5) * cols as f64) / SIDE as f64) as usize;
            let inj = inj.min(cols - 1);
            *cell = luma[ini * cols + inj];
        }
    }

    (quality(&grid), dct_16(&grid))
}

fn window_size(old: usize) -> usize {
    old.div_ceil(2 * SIDE)
}

fn box_1d(input: &[f32], output: &mut [f32], stride: usize, len: usize, window: usize) {
    let window = window.clamp(1, len.max(1));
    let half = (window + 2) / 2;
    let phase1 = half - 1;
    let phase2 = window - half + 1;
    let phase3 = len.saturating_sub(window);
    let phase4 = half - 1;

    let mut li = 0usize;
    let mut ri = 0usize;
    let mut oi = 0usize;
    let mut sum = 0f32;
    let mut size = 0f32;

    let read = |at: usize| input.get(at).copied().unwrap_or(0.0);

    for _ in 0..phase1 {
        sum += read(ri);
        size += 1.0;
        ri += stride;
    }
    for _ in 0..phase2 {
        sum += read(ri);
        size += 1.0;
        if let Some(out) = output.get_mut(oi) {
            *out = sum / size;
        }
        ri += stride;
        oi += stride;
    }
    for _ in 0..phase3 {
        sum += read(ri);
        sum -= read(li);
        if let Some(out) = output.get_mut(oi) {
            *out = sum / size;
        }
        li += stride;
        ri += stride;
        oi += stride;
    }
    for _ in 0..phase4 {
        sum -= read(li);
        size -= 1.0;
        if let Some(out) = output.get_mut(oi) {
            *out = if size > 0.0 { sum / size } else { 0.0 };
        }
        li += stride;
        oi += stride;
    }
}

fn quality(grid: &[[f32; SIDE]; SIDE]) -> u8 {
    let step = |u: f32, v: f32| (((u - v) * 100.0 / 255.0) as i64).abs();
    let mut gradient: i64 = 0;

    for pair in grid.windows(2) {
        gradient += pair[0]
            .iter()
            .zip(&pair[1])
            .map(|(u, v)| step(*u, *v))
            .sum::<i64>();
    }
    for row in grid {
        gradient += row
            .windows(2)
            .map(|pair| step(pair[0], pair[1]))
            .sum::<i64>();
    }

    (gradient / 90).clamp(0, 100) as u8
}

fn dct_16(grid: &[[f32; SIDE]; SIDE]) -> [[f32; DCT]; DCT] {
    let scale = (2.0f64 / SIDE as f64).sqrt();
    let mut matrix = [[0f32; SIDE]; DCT];
    for (i, row) in matrix.iter_mut().enumerate() {
        for (j, cell) in row.iter_mut().enumerate() {
            let angle = (std::f64::consts::PI / 2.0 / SIDE as f64)
                * (i as f64 + 1.0)
                * (2.0 * j as f64 + 1.0);
            *cell = (scale * angle.cos()) as f32;
        }
    }

    let mut partial = [[0f32; SIDE]; DCT];
    for (partial_row, matrix_row) in partial.iter_mut().zip(&matrix) {
        for (j, cell) in partial_row.iter_mut().enumerate() {
            *cell = matrix_row.iter().zip(grid).map(|(m, g)| m * g[j]).sum();
        }
    }

    let mut out = [[0f32; DCT]; DCT];
    for (out_row, partial_row) in out.iter_mut().zip(&partial) {
        for (cell, matrix_row) in out_row.iter_mut().zip(&matrix) {
            *cell = partial_row.iter().zip(matrix_row).map(|(p, m)| p * m).sum();
        }
    }

    out
}

pub fn hamming(a: &str, b: &str) -> Option<u32> {
    let mut left = [0u8; 32];
    let mut right = [0u8; 32];
    hex::decode_to_slice(a, &mut left).ok()?;
    hex::decode_to_slice(b, &mut right).ok()?;

    Some(
        left.iter()
            .zip(&right)
            .map(|(x, y)| (x ^ y).count_ones())
            .sum(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use image::codecs::jpeg::JpegEncoder;
    use image::{Rgb, RgbImage};

    fn hash_bytes(bytes: &[u8], format: &str, max_pixels: u64) -> Option<Pdq> {
        fingerprint(bytes, format, max_pixels).pdq
    }

    fn hash_image(image: &DynamicImage) -> Pdq {
        variants(image.clone(), false).primary
    }

    fn scene(width: u32, height: u32) -> DynamicImage {
        let image = RgbImage::from_fn(width, height, |x, y| {
            let fx = x as f32 / width as f32;
            let fy = y as f32 / height as f32;
            let dx = fx - 0.3;
            let dy = fy - 0.6;
            let blob = if dx * dx + dy * dy < 0.04 { 120.0 } else { 0.0 };
            let tile = if ((fx * 12.0) as u32 + (fy * 8.0) as u32).is_multiple_of(2) {
                70.0
            } else {
                0.0
            };
            let wave = ((fx * 9.0).sin() * (fy * 5.0).cos() + 1.0) * 60.0 + tile;
            let r = (fx * 255.0).min(255.0);
            let g = (wave + blob).min(255.0);
            let b = (fy * 200.0 + if fx > 0.7 { 50.0 } else { 0.0 }).min(255.0);
            Rgb([r as u8, g as u8, b as u8])
        });
        DynamicImage::ImageRgb8(image)
    }

    fn png(image: &DynamicImage) -> Vec<u8> {
        let mut out = Cursor::new(Vec::new());
        image
            .write_to(&mut out, ImageFormat::Png)
            .expect("png encodes");
        out.into_inner()
    }

    fn jpeg(image: &DynamicImage, quality: u8) -> Vec<u8> {
        let mut out = Vec::new();
        image
            .write_with_encoder(JpegEncoder::new_with_quality(&mut out, quality))
            .expect("jpeg encodes");
        out
    }

    #[test]
    fn the_hash_is_64_lowercase_hex_characters() {
        let pdq = hash_image(&scene(200, 150));

        assert_eq!(pdq.hash.len(), 64);
        assert!(pdq
            .hash
            .chars()
            .all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c)));
        assert!(pdq.quality <= 100);
    }

    #[test]
    fn a_png_and_a_jpeg_of_the_same_picture_hash_within_the_match_threshold() {
        let image = scene(320, 240);

        let lossless = hash_bytes(&png(&image), "png", 100_000_000).expect("png hashes");
        let lossy = hash_bytes(&jpeg(&image, 80), "jpeg", 100_000_000).expect("jpeg hashes");

        let distance = hamming(&lossless.hash, &lossy.hash).expect("two hashes");
        assert!(distance <= 31, "distance {distance}");
    }

    #[test]
    fn a_large_picture_is_scaled_before_hashing_and_still_matches() {
        let small = hash_image(&scene(300, 200));
        let large = hash_image(&scene(1200, 800));

        let distance = hamming(&small.hash, &large.hash).expect("two hashes");
        assert!(distance <= 31, "distance {distance}");
    }

    #[test]
    fn an_inverted_picture_is_far_from_the_original() {
        let original = scene(256, 256);
        let mut inverted = original.clone();
        inverted.invert();

        let distance =
            hamming(&hash_image(&original).hash, &hash_image(&inverted).hash).expect("two hashes");
        assert!(distance > 128, "distance {distance}");
    }

    #[test]
    fn a_flat_picture_has_no_quality() {
        let flat = DynamicImage::ImageRgb8(RgbImage::from_pixel(128, 128, Rgb([90, 90, 90])));

        assert_eq!(hash_image(&flat).quality, 0);
    }

    #[test]
    fn a_textured_picture_has_quality() {
        assert!(hash_image(&scene(256, 256)).quality > 0);
    }

    #[test]
    fn bytes_that_are_not_an_image_yield_nothing() {
        assert_eq!(hash_bytes(b"", "png", 100_000_000), None);
        assert_eq!(hash_bytes(b"not an image", "jpeg", 100_000_000), None);
        assert_eq!(
            hash_bytes(&png(&scene(40, 40))[..30], "png", 100_000_000),
            None
        );
    }

    #[test]
    fn a_picture_over_the_pixel_cap_is_not_hashed() {
        assert_eq!(hash_bytes(&png(&scene(64, 64)), "png", 1000), None);
    }

    #[test]
    fn a_one_pixel_picture_hashes_without_panicking() {
        let one = DynamicImage::ImageRgb8(RgbImage::from_pixel(1, 1, Rgb([10, 20, 30])));

        assert_eq!(hash_image(&one).hash.len(), 64);
    }

    #[test]
    fn hamming_refuses_malformed_hashes() {
        assert_eq!(hamming("ab", "ab"), None);
        assert_eq!(hamming(&"0".repeat(64), &"f".repeat(64)), Some(256));
    }

    fn transparent_scene(width: u32, height: u32) -> DynamicImage {
        let base = scene(width, height).to_rgba8();
        let image = image::RgbaImage::from_fn(width, height, |x, y| {
            let mut p = *base.get_pixel(x, y);
            let dx = x as f32 / width as f32 - 0.5;
            let dy = y as f32 / height as f32 - 0.5;
            if dx * dx + dy * dy > 0.16 {
                p = image::Rgba([0, 0, 0, 0]);
            }
            p
        });
        DynamicImage::ImageRgba8(image)
    }

    fn flatten(image: &DynamicImage, background: u8) -> DynamicImage {
        let rgba = image.to_rgba8();
        DynamicImage::ImageRgb8(RgbImage::from_fn(rgba.width(), rgba.height(), |x, y| {
            let p = rgba.get_pixel(x, y);
            let alpha = f32::from(p[3]) / 255.0;
            let mix = |c: u8| (f32::from(c) * alpha + f32::from(background) * (1.0 - alpha)) as u8;
            Rgb([mix(p[0]), mix(p[1]), mix(p[2])])
        }))
    }

    fn gif(frames: &[(DynamicImage, u32)]) -> Vec<u8> {
        let mut out = Vec::new();
        {
            let mut encoder = image::codecs::gif::GifEncoder::new(&mut out);
            for (image, delay_ms) in frames {
                let frame = image::Frame::from_parts(
                    image.to_rgba8(),
                    0,
                    0,
                    image::Delay::from_numer_denom_ms(*delay_ms, 1),
                );
                encoder.encode_frame(frame).expect("gif frame encodes");
            }
        }
        out
    }

    fn other_scene(width: u32, height: u32) -> DynamicImage {
        let mut image = scene(width, height);
        image = image.rotate90();
        image.resize_exact(width, height, image::imageops::FilterType::Triangle)
    }

    #[test]
    fn a_transparent_picture_matches_its_copy_flattened_onto_white_or_black() {
        let original = transparent_scene(256, 256);
        let print = fingerprint(&png(&original), "png", 100_000_000);
        let pdq = print.pdq.expect("hashed");
        let black = print
            .black
            .expect("a transparent picture has a black variant");

        let on_white = hash_image(&flatten(&original, 255));
        let on_black = hash_image(&flatten(&original, 0));

        assert!(hamming(&pdq.hash, &on_white.hash).unwrap() <= MATCH_DISTANCE);
        assert!(hamming(&black, &on_black.hash).unwrap() <= MATCH_DISTANCE);
    }

    #[test]
    fn an_opaque_picture_has_no_black_variant() {
        let print = fingerprint(&png(&scene(200, 150)), "png", 100_000_000);

        assert!(print.pdq.is_some());
        assert_eq!(print.black, None);
        assert_eq!(print.mirrors.len(), 2);
    }

    #[test]
    fn a_mirrored_copy_is_found_through_the_mirror_probes() {
        let original = scene(320, 240);
        let print = fingerprint(&png(&original), "png", 100_000_000);

        let flipped_h = hash_image(&original.fliph()).hash;
        let flipped_v = hash_image(&original.flipv()).hash;

        assert!(hamming(&print.mirrors[0], &flipped_h).unwrap() <= MATCH_DISTANCE);
        assert!(hamming(&print.mirrors[1], &flipped_v).unwrap() <= MATCH_DISTANCE);
        assert!(hamming(&print.pdq.unwrap().hash, &flipped_h).unwrap() > MATCH_DISTANCE);
    }

    #[test]
    fn an_unrelated_picture_is_far_from_every_variant() {
        let print = fingerprint(&png(&scene(256, 256)), "png", 100_000_000);
        let unrelated = hash_image(&other_scene(256, 256)).hash;

        for hash in std::iter::once(print.pdq.unwrap().hash).chain(print.mirrors) {
            assert!(hamming(&hash, &unrelated).unwrap() > MATCH_DISTANCE);
        }
    }

    #[test]
    fn a_side_over_the_cap_is_not_decoded() {
        let wide = DynamicImage::ImageRgb8(RgbImage::from_pixel(MAX_SIDE + 1, 2, Rgb([1, 2, 3])));

        assert_eq!(
            fingerprint(&png(&wide), "png", u64::MAX),
            Fingerprint::default()
        );
    }

    #[test]
    fn an_animated_gif_keeps_one_frame_per_second_and_drops_repeats() {
        let a = scene(128, 96);
        let b = other_scene(128, 96);
        let bytes = gif(&[
            (a.clone(), 1000),
            (a.clone(), 1000),
            (b.clone(), 1000),
            (b, 200),
        ]);

        let print = fingerprint(&bytes, "gif", 100_000_000);

        assert_eq!(print.frames.len(), 2, "{:?}", print.frames);
        assert_eq!(print.pdq.as_ref().map(|p| &p.hash), print.frames.first());
    }

    #[test]
    fn a_still_gif_reduces_to_one_hash_with_mirrors() {
        let image = scene(160, 120);
        let print = fingerprint(&gif(&[(image.clone(), 0)]), "gif", 100_000_000);

        assert!(print.frames.is_empty());
        assert_eq!(print.mirrors.len(), 2);
        let distance = hamming(&print.pdq.unwrap().hash, &hash_image(&image).hash).unwrap();
        assert!(distance <= MATCH_DISTANCE, "distance {distance}");
    }

    #[test]
    fn a_gif_frame_count_beyond_the_cap_stops_decoding() {
        let frames: Vec<(DynamicImage, u32)> = (0..(MAX_FRAMES + 20))
            .map(|i| {
                (
                    if i % 2 == 0 {
                        scene(16, 16)
                    } else {
                        other_scene(16, 16)
                    },
                    1000,
                )
            })
            .collect();

        let print = fingerprint(&gif(&frames), "gif", 100_000_000);

        assert!(print.frames.len() <= MAX_KEPT_FRAMES);
    }

    #[test]
    fn unknown_formats_are_not_fingerprinted() {
        assert_eq!(
            fingerprint(&png(&scene(40, 40)), "pdf", 100_000_000),
            Fingerprint::default()
        );
    }

    #[test]
    fn a_gif_declaring_a_huge_screen_is_not_decoded() {
        let mut bytes = b"GIF89a".to_vec();
        bytes.extend_from_slice(&u16::MAX.to_le_bytes());
        bytes.extend_from_slice(&u16::MAX.to_le_bytes());
        bytes.extend_from_slice(&[0, 0, 0, 0x3b]);

        assert_eq!(fingerprint(&bytes, "gif", u64::MAX), Fingerprint::default());
    }

    #[test]
    fn bytes_are_decoded_only_as_the_declared_format() {
        let bytes = jpeg(&scene(64, 48), 90);

        assert!(fingerprint(&bytes, "jpeg", 100_000_000).pdq.is_some());
        assert_eq!(
            fingerprint(&bytes, "png", 100_000_000),
            Fingerprint::default()
        );
        assert_eq!(
            fingerprint(&bytes, "avif", 100_000_000),
            Fingerprint::default()
        );
    }

    #[test]
    fn hamming_refuses_non_hex_input() {
        assert_eq!(hamming(&"g".repeat(64), &"0".repeat(64)), None);
        assert_eq!(hamming(&"0".repeat(66), &"0".repeat(66)), None);
    }

    #[test]
    fn an_animated_gif_carries_mirrors_of_its_first_kept_frame() {
        let a = scene(128, 96);
        let b = other_scene(128, 96);
        let print = fingerprint(&gif(&[(a.clone(), 1000), (b, 1000)]), "gif", 100_000_000);
        let first = fingerprint(&gif(&[(a, 1000)]), "gif", 100_000_000);

        assert_eq!(print.frames.len(), 2);
        assert_eq!(print.mirrors.len(), 2);
        assert_eq!(print.mirrors, first.mirrors);
        assert_eq!(print.pdq, first.pdq);
    }

    #[test]
    fn a_flat_opening_frame_is_skipped_for_the_first_kept_frame() {
        let flat = DynamicImage::ImageRgb8(RgbImage::from_pixel(128, 96, Rgb([90, 90, 90])));
        let picture = scene(128, 96);
        let print = fingerprint(
            &gif(&[(flat, 1000), (picture.clone(), 1000)]),
            "gif",
            100_000_000,
        );

        let pdq = print.pdq.expect("hashed");
        assert!(pdq.quality >= MIN_QUALITY);
        assert!(hamming(&pdq.hash, &hash_image(&picture).hash).unwrap() <= MATCH_DISTANCE);
        assert!(print.frames.is_empty());
    }

    #[test]
    fn a_gif_of_flat_frames_still_reports_its_first_frame() {
        let flat = DynamicImage::ImageRgb8(RgbImage::from_pixel(32, 32, Rgb([90, 90, 90])));
        let print = fingerprint(
            &gif(&[(flat.clone(), 1000), (flat, 1000)]),
            "gif",
            100_000_000,
        );

        assert_eq!(print.pdq.map(|p| p.quality), Some(0));
        assert!(print.frames.is_empty());
    }

    #[cfg(feature = "avif")]
    #[test]
    fn an_avif_is_fingerprinted_and_measured_without_a_second_decode() {
        let bytes = include_bytes!("../tests/fixtures/scene.avif");

        let print = fingerprint(bytes, "avif", 100_000_000);

        assert!(print.pdq.is_some());
        assert_eq!(print.mirrors.len(), 2);
        assert_eq!(
            crate::media::dimensions(bytes, 100_000_000).unwrap(),
            Some((160, 120))
        );
    }

    #[cfg(feature = "avif")]
    #[test]
    fn an_avif_over_the_pixel_cap_is_not_decoded() {
        let bytes = include_bytes!("../tests/fixtures/scene.avif");

        assert_eq!(fingerprint(bytes, "avif", 1000), Fingerprint::default());
        assert_eq!(
            fingerprint(&bytes[..bytes.len() / 2], "avif", u64::MAX),
            Fingerprint::default()
        );
    }

    #[cfg(feature = "heic")]
    #[test]
    fn a_heic_over_the_pixel_cap_is_not_decoded() {
        let bytes = include_bytes!("../tests/fixtures/scene.heic");

        assert!(fingerprint(bytes, "heic", 100_000_000).pdq.is_some());
        assert_eq!(fingerprint(bytes, "heic", 1000), Fingerprint::default());
    }

    #[cfg(all(feature = "avif", feature = "heic"))]
    #[test]
    fn an_avif_and_a_heic_of_the_same_picture_match() {
        let avif = fingerprint(
            include_bytes!("../tests/fixtures/scene.avif"),
            "avif",
            100_000_000,
        );
        let heic = fingerprint(
            include_bytes!("../tests/fixtures/scene.heic"),
            "heic",
            100_000_000,
        );

        let distance = hamming(&avif.pdq.unwrap().hash, &heic.pdq.unwrap().hash).unwrap();
        assert!(distance <= MATCH_DISTANCE, "distance {distance}");
    }
}

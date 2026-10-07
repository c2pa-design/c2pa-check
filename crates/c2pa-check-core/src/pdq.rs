use std::io::Cursor;
use std::panic::{catch_unwind, AssertUnwindSafe};

use image::{DynamicImage, ImageReader, Limits};

const SIDE: usize = 64;
const DCT: usize = 16;
const PRESCALE: u32 = 512;
const MAX_DECODE_ALLOC: u64 = 256 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pdq {
    pub hash: String,
    pub quality: u8,
}

pub fn hash_bytes(bytes: &[u8], max_pixels: u64) -> Option<Pdq> {
    catch_unwind(AssertUnwindSafe(|| {
        decode(bytes, max_pixels).map(|img| hash_image(&img))
    }))
    .ok()
    .flatten()
}

fn decode(bytes: &[u8], max_pixels: u64) -> Option<DynamicImage> {
    let mut reader = ImageReader::new(Cursor::new(bytes))
        .with_guessed_format()
        .ok()?;

    let side = u32::try_from(max_pixels).unwrap_or(u32::MAX);
    let mut limits = Limits::default();
    limits.max_image_width = Some(side);
    limits.max_image_height = Some(side);
    limits.max_alloc = Some(MAX_DECODE_ALLOC);
    reader.limits(limits);

    let image = reader.decode().ok()?;
    if u64::from(image.width()) * u64::from(image.height()) > max_pixels {
        return None;
    }

    Some(image)
}

pub fn hash_image(image: &DynamicImage) -> Pdq {
    let image = if image.width() > PRESCALE || image.height() > PRESCALE {
        image.thumbnail(PRESCALE, PRESCALE)
    } else {
        image.clone()
    };

    let rgb = image.to_rgb8();
    let cols = rgb.width() as usize;
    let rows = rgb.height() as usize;

    if cols == 0 || rows == 0 {
        return Pdq {
            hash: "0".repeat(64),
            quality: 0,
        };
    }

    let mut luma: Vec<f32> = rgb
        .pixels()
        .map(|p| 0.299 * f32::from(p[0]) + 0.587 * f32::from(p[1]) + 0.114 * f32::from(p[2]))
        .collect();

    hash_luma(&mut luma, rows, cols)
}

fn hash_luma(luma: &mut [f32], rows: usize, cols: usize) -> Pdq {
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

    let quality = quality(&grid);
    let dct = dct_16(&grid);

    let mut sorted: Vec<f32> = dct.iter().flatten().copied().collect();
    sorted.sort_by(f32::total_cmp);
    let median = sorted[DCT * DCT / 2 - 1];

    let mut words = [0u16; DCT];
    for (i, row) in dct.iter().enumerate() {
        for (j, value) in row.iter().enumerate() {
            if *value > median {
                words[i] |= 1 << j;
            }
        }
    }

    let hash = words.iter().rev().map(|w| format!("{w:04x}")).collect();

    Pdq { hash, quality }
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
    if a.len() != 64 || b.len() != 64 {
        return None;
    }
    let a = hex::decode(a).ok()?;
    let b = hex::decode(b).ok()?;

    Some(a.iter().zip(&b).map(|(x, y)| (x ^ y).count_ones()).sum())
}

#[cfg(test)]
mod tests {
    use super::*;
    use image::codecs::jpeg::JpegEncoder;
    use image::{ImageFormat, Rgb, RgbImage};

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

        let lossless = hash_bytes(&png(&image), 100_000_000).expect("png hashes");
        let lossy = hash_bytes(&jpeg(&image, 80), 100_000_000).expect("jpeg hashes");

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
        assert_eq!(hash_bytes(b"", 100_000_000), None);
        assert_eq!(hash_bytes(b"not an image", 100_000_000), None);
        assert_eq!(hash_bytes(&png(&scene(40, 40))[..30], 100_000_000), None);
    }

    #[test]
    fn a_picture_over_the_pixel_cap_is_not_hashed() {
        assert_eq!(hash_bytes(&png(&scene(64, 64)), 1000), None);
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
}

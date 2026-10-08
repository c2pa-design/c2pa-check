use std::io::Cursor;

use mp4parse::ParseStrictness;

const OBU_SEQUENCE_HEADER: u8 = 1;
const LEB128_MAX_BYTES: usize = 8;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CodedSize {
    pub width: u32,
    pub height: u32,
    pub limit_width: u32,
    pub limit_height: u32,
}

impl CodedSize {
    fn widest(self, other: Self) -> Self {
        Self {
            width: self.width.max(other.width),
            height: self.height.max(other.height),
            limit_width: self.limit_width.max(other.limit_width),
            limit_height: self.limit_height.max(other.limit_height),
        }
    }
}

pub fn coded_size(bytes: &[u8]) -> Option<CodedSize> {
    let context = mp4parse::read_avif(&mut Cursor::new(bytes), ParseStrictness::Normal).ok()?;
    let primary = sequence_size(context.primary_item_coded_data()?)?;

    match context.alpha_item_coded_data() {
        Some(alpha) => Some(primary.widest(sequence_size(alpha)?)),
        None => Some(primary),
    }
}

fn sequence_size(data: &[u8]) -> Option<CodedSize> {
    let mut found: Option<CodedSize> = None;
    let mut rest = data;

    while let Some((&header, tail)) = rest.split_first() {
        let kind = (header >> 3) & 0x0f;
        let tail = if header & 0x04 != 0 {
            tail.get(1..)?
        } else {
            tail
        };
        let (size, tail) = if header & 0x02 != 0 {
            leb128(tail)?
        } else {
            (tail.len(), tail)
        };
        let payload = tail.get(..size)?;
        if kind == OBU_SEQUENCE_HEADER {
            let size = sequence_header(payload)?;
            found = Some(found.map_or(size, |seen| seen.widest(size)));
        }
        rest = tail.get(size..)?;
    }

    found
}

fn leb128(data: &[u8]) -> Option<(usize, &[u8])> {
    let mut value = 0u64;
    for (i, byte) in data.iter().take(LEB128_MAX_BYTES).enumerate() {
        value |= u64::from(byte & 0x7f) << (7 * i);
        if byte & 0x80 == 0 {
            return Some((usize::try_from(value).ok()?, data.get(i + 1..)?));
        }
    }

    None
}

fn sequence_header(payload: &[u8]) -> Option<CodedSize> {
    let mut bits = BitReader::new(payload);
    bits.read(3)?;
    bits.read(1)?;
    let reduced = bits.flag()?;

    if reduced {
        bits.read(5)?;
    } else {
        let mut decoder_model = false;
        let mut delay_bits = 0;
        if bits.flag()? {
            bits.read(32)?;
            bits.read(32)?;
            if bits.flag()? {
                bits.uvlc()?;
            }
            decoder_model = bits.flag()?;
            if decoder_model {
                delay_bits = bits.read(5)? + 1;
                bits.read(32)?;
                bits.read(5)?;
                bits.read(5)?;
            }
        }
        let initial_delay = bits.flag()?;
        let points = bits.read(5)? + 1;
        for _ in 0..points {
            bits.read(12)?;
            if bits.read(5)? > 7 {
                bits.read(1)?;
            }
            if decoder_model && bits.flag()? {
                bits.read(delay_bits)?;
                bits.read(delay_bits)?;
                bits.read(1)?;
            }
            if initial_delay && bits.flag()? {
                bits.read(4)?;
            }
        }
    }

    let width_bits = bits.read(4)? + 1;
    let height_bits = bits.read(4)? + 1;
    let width = bits.read(width_bits)? + 1;
    let height = bits.read(height_bits)? + 1;
    let (limit_width, limit_height) = if reduced {
        (width, height)
    } else {
        (1 << width_bits, 1 << height_bits)
    };

    Some(CodedSize {
        width,
        height,
        limit_width,
        limit_height,
    })
}

struct BitReader<'a> {
    data: &'a [u8],
    at: usize,
}

impl<'a> BitReader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, at: 0 }
    }

    fn read(&mut self, count: u32) -> Option<u32> {
        let mut value = 0u32;
        for _ in 0..count.min(32) {
            let byte = *self.data.get(self.at / 8)?;
            value = (value << 1) | u32::from((byte >> (7 - self.at % 8)) & 1);
            self.at += 1;
        }

        Some(value)
    }

    fn flag(&mut self) -> Option<bool> {
        self.read(1).map(|bit| bit == 1)
    }

    fn uvlc(&mut self) -> Option<()> {
        let mut zeros = 0u32;
        while !self.flag()? {
            zeros = zeros.saturating_add(1);
        }
        if zeros < 32 {
            self.read(zeros)?;
        }

        Some(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct BitWriter {
        bytes: Vec<u8>,
        bits: usize,
    }

    impl BitWriter {
        fn put(&mut self, count: u32, value: u32) -> &mut Self {
            for shift in (0..count).rev() {
                if self.bits.is_multiple_of(8) {
                    self.bytes.push(0);
                }
                let bit = ((value >> shift) & 1) as u8;
                if let Some(last) = self.bytes.last_mut() {
                    *last |= bit << (7 - self.bits % 8);
                }
                self.bits += 1;
            }
            self
        }
    }

    fn reduced_header(width: u32, height: u32) -> Vec<u8> {
        let mut bits = BitWriter::default();
        bits.put(3, 0).put(1, 1).put(1, 1).put(5, 8);
        bits.put(4, 15)
            .put(4, 15)
            .put(16, width - 1)
            .put(16, height - 1);
        bits.bytes
    }

    fn full_header(width: u32, height: u32) -> Vec<u8> {
        let mut bits = BitWriter::default();
        bits.put(3, 0).put(1, 0).put(1, 0);
        bits.put(1, 1)
            .put(32, 1)
            .put(32, 30)
            .put(1, 1)
            .put(3, 0b010);
        bits.put(1, 1).put(5, 9).put(32, 1).put(5, 4).put(5, 4);
        bits.put(1, 1).put(5, 1);
        for _ in 0..2 {
            bits.put(12, 0).put(5, 9).put(1, 0);
            bits.put(1, 1).put(10, 3).put(10, 4).put(1, 0);
            bits.put(1, 1).put(4, 2);
        }
        bits.put(4, 11)
            .put(4, 10)
            .put(12, width - 1)
            .put(11, height - 1);
        bits.bytes
    }

    fn obu(kind: u8, payload: &[u8]) -> Vec<u8> {
        let mut out = vec![(kind << 3) | 0x02];
        let mut size = payload.len();
        loop {
            let byte = (size & 0x7f) as u8;
            size >>= 7;
            if size == 0 {
                out.push(byte);
                break;
            }
            out.push(byte | 0x80);
        }
        out.extend_from_slice(payload);
        out
    }

    #[test]
    fn a_reduced_still_picture_header_bounds_the_frame_by_its_size() {
        let data = [
            obu(2, &[]),
            obu(OBU_SEQUENCE_HEADER, &reduced_header(640, 480)),
        ]
        .concat();

        assert_eq!(
            sequence_size(&data),
            Some(CodedSize {
                width: 640,
                height: 480,
                limit_width: 640,
                limit_height: 480,
            })
        );
    }

    #[test]
    fn a_full_header_bounds_the_frame_by_its_field_widths() {
        let data = obu(OBU_SEQUENCE_HEADER, &full_header(4000, 1500));

        assert_eq!(
            sequence_size(&data),
            Some(CodedSize {
                width: 4000,
                height: 1500,
                limit_width: 4096,
                limit_height: 2048,
            })
        );
    }

    #[test]
    fn the_widest_of_several_sequence_headers_wins() {
        let data = [
            obu(OBU_SEQUENCE_HEADER, &reduced_header(64, 64)),
            obu(OBU_SEQUENCE_HEADER, &reduced_header(9000, 32)),
        ]
        .concat();

        let size = sequence_size(&data).expect("a size");

        assert_eq!((size.limit_width, size.limit_height), (9000, 64));
    }

    #[test]
    fn data_without_a_sequence_header_has_no_size() {
        assert_eq!(sequence_size(&obu(6, &[1, 2, 3])), None);
        assert_eq!(sequence_size(&[]), None);
    }

    #[test]
    fn truncated_or_oversized_obus_are_refused() {
        let header = obu(OBU_SEQUENCE_HEADER, &reduced_header(640, 480));

        assert_eq!(sequence_size(&header[..header.len() - 1]), None);
        assert_eq!(
            sequence_size(&[0x0a, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01]),
            None
        );
        assert_eq!(sequence_size(&[0x0a, 0x7f]), None);
        assert_eq!(sequence_size(&[0x0e]), None);
    }

    #[test]
    fn a_header_cut_short_is_refused() {
        let header = reduced_header(640, 480);

        assert_eq!(sequence_header(&header[..3]), None);
    }

    #[test]
    fn bytes_that_are_not_avif_have_no_size() {
        assert_eq!(coded_size(b""), None);
        assert_eq!(coded_size(b"\0\0\0\x14ftypavif\0\0\0\0avif"), None);
    }

    #[test]
    fn a_long_run_of_zero_bits_in_uvlc_ends_at_the_data() {
        let zeros = [0u8; 16];

        assert_eq!(BitReader::new(&zeros).uvlc(), None);
        assert_eq!(
            BitReader::new(&[0x00, 0x00, 0x00, 0x00, 0x80]).uvlc(),
            Some(())
        );
    }
}

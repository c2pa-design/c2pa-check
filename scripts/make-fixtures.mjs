#!/usr/bin/env node
import { mkdirSync, writeFileSync } from 'node:fs'
import { deflateSync } from 'node:zlib'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

/**
 * Generates the fixtures that need no signing key: files with no manifest, and the malformed
 * and oversized inputs the limits exist for. Everything here is deterministic, so the corpus
 * is reproducible from source rather than a pile of committed binaries nobody can regenerate.
 *
 * The signed fixtures cannot be generated here — they need c2patool and a certificate. See
 * `fixtures/README.md` for the exact commands and record them beside each file.
 */
const root = join(dirname(fileURLToPath(import.meta.url)), '..', 'fixtures')

function png(width, height, { pixels, bitDepth = 8, colorType = 6 } = {}) {
  const chunk = (type, data) => {
    const length = Buffer.alloc(4)
    length.writeUInt32BE(data.length)
    const body = Buffer.concat([Buffer.from(type, 'ascii'), data])
    const crc = Buffer.alloc(4)
    crc.writeUInt32BE(crc32(body) >>> 0)

    return Buffer.concat([length, body, crc])
  }

  const ihdr = Buffer.alloc(13)
  ihdr.writeUInt32BE(width, 0)
  ihdr.writeUInt32BE(height, 4)
  ihdr[8] = bitDepth
  ihdr[9] = colorType
  ihdr[10] = 0
  ihdr[11] = 0
  ihdr[12] = 0

  const body = pixels ?? Buffer.alloc(0)

  return Buffer.concat([
    Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]),
    chunk('IHDR', ihdr),
    chunk('IDAT', deflateSync(body)),
    chunk('IEND', Buffer.alloc(0)),
  ])
}

let crcTable = null

function crc32(buffer) {
  if (!crcTable) {
    crcTable = new Int32Array(256)
    for (let n = 0; n < 256; n++) {
      let c = n
      for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1
      crcTable[n] = c
    }
  }

  let crc = -1
  for (const byte of buffer) crc = crcTable[(crc ^ byte) & 0xff] ^ (crc >>> 8)

  return crc ^ -1
}

/** A JPEG with a single grey MCU: enough that a reader accepts the container. */
function jpeg({ trailing = Buffer.alloc(0) } = {}) {
  const quant = Buffer.alloc(64, 16)
  const segment = (marker, payload) => {
    const length = Buffer.alloc(2)
    length.writeUInt16BE(payload.length + 2)

    return Buffer.concat([Buffer.from([0xff, marker]), length, payload])
  }

  const sof0 = Buffer.from([0x08, 0x00, 0x08, 0x00, 0x08, 0x01, 0x01, 0x11, 0x00])
  const huffman = Buffer.concat([
    Buffer.from([0x00]),
    Buffer.from([0, 1, ...new Array(15).fill(0)]),
    Buffer.from([0x00]),
  ])
  const sos = Buffer.from([0x01, 0x01, 0x00, 0x00, 0x3f, 0x00])

  return Buffer.concat([
    Buffer.from([0xff, 0xd8]),
    segment(0xdb, Buffer.concat([Buffer.from([0x00]), quant])),
    segment(0xc0, sof0),
    segment(0xc4, huffman),
    segment(0xda, sos),
    Buffer.from([0x00, 0x00]),
    Buffer.from([0xff, 0xd9]),
    trailing,
  ])
}

/** A minimal lossless WebP: RIFF container plus a VP8L chunk. */
function webp() {
  const vp8l = Buffer.from([0x2f, 0x00, 0x00, 0x00, 0x00, 0x88, 0x88, 0x08])
  const chunk = Buffer.concat([Buffer.from('VP8L', 'ascii'), sizeOf(vp8l), vp8l])
  const riff = Buffer.concat([Buffer.from('WEBP', 'ascii'), chunk])

  return Buffer.concat([Buffer.from('RIFF', 'ascii'), sizeOf(riff), riff])
}

function sizeOf(buffer) {
  const size = Buffer.alloc(4)
  size.writeUInt32LE(buffer.length)

  return size
}

/** A truncated JUMBF box: the container is readable, the manifest is not. */
function truncatedJumbf() {
  const box = Buffer.concat([
    Buffer.from([0x00, 0x00, 0x40, 0x00]),
    Buffer.from('jumb', 'ascii'),
    Buffer.from('c2pa', 'ascii'),
    Buffer.alloc(32, 0x41),
  ])
  const length = Buffer.alloc(2)
  length.writeUInt16BE(box.length + 2)

  return jpeg({ trailing: Buffer.concat([Buffer.from([0xff, 0xeb]), length, box]) })
}

const files = {
  'jpeg/no-manifest.jpg': jpeg(),
  'jpeg/corrupted-manifest.jpg': truncatedJumbf(),
  'png/no-manifest.png': png(8, 8, { pixels: Buffer.alloc(8 * 9, 0) }),
  'webp/no-manifest.webp': webp(),
  // 60000 × 60000 declared in the header. Nothing decodes it: the dimension cap refuses it
  // from the header alone, which is the behaviour the cap exists to have.
  'bombs/huge-dimensions.png': png(60000, 60000, { pixels: Buffer.alloc(64, 0) }),
  // 64 MB of zeroes deflates to a few kilobytes. A reader that decompresses before checking
  // the size allocates all of it.
  'bombs/decompression.png': png(4096, 4096, { pixels: Buffer.alloc(64 * 1024 * 1024, 0) }),
}

const expected = {
  'jpeg/no-manifest.jpg': { credential: 'absent', note: 'the ordinary state of most files' },
  'jpeg/corrupted-manifest.jpg': { credential: 'absent', note: 'a truncated JUMBF box is not a manifest; the container still reads' },
  'png/no-manifest.png': { credential: 'absent' },
  'webp/no-manifest.webp': { credential: 'absent' },
  'bombs/huge-dimensions.png': { error: 'limit_exceeded', note: 'refused from the header, never allocated' },
  'bombs/decompression.png': { error: 'limit_exceeded', note: 'refused by the byte cap before inflate' },
}

for (const [name, buffer] of Object.entries(files)) {
  const path = join(root, name)
  mkdirSync(dirname(path), { recursive: true })
  writeFileSync(path, buffer)

  writeFileSync(
    `${path.replace(/\.[^.]+$/, '')}.expected.json`,
    `${JSON.stringify(expected[name], null, 2)}\n`,
  )

  console.log(`${name}  ${buffer.length} bytes`)
}

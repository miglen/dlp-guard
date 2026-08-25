#!/usr/bin/env node
// make-icons.mjs — renders the DLP Guard shield icon to icons/icon{16,48,128}.png
// Pure Node (zlib) PNG encoder; no dependencies.
import { deflateSync } from 'node:zlib';
import { writeFileSync, mkdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const OUT_DIR = join(__dirname, '..', 'icons');
mkdirSync(OUT_DIR, { recursive: true });

function crc32(buf) {
  let c, table = crc32.table;
  if (!table) {
    table = crc32.table = new Int32Array(256);
    for (let n = 0; n < 256; n++) {
      c = n;
      for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
      table[n] = c;
    }
  }
  c = 0 ^ -1;
  for (let i = 0; i < buf.length; i++) c = (c >>> 8) ^ table[(c ^ buf[i]) & 0xff];
  return (c ^ -1) >>> 0;
}

function chunk(type, data) {
  const len = Buffer.alloc(4);
  len.writeUInt32BE(data.length);
  const body = Buffer.concat([Buffer.from(type, 'ascii'), data]);
  const crc = Buffer.alloc(4);
  crc.writeUInt32BE(crc32(body));
  return Buffer.concat([len, body, crc]);
}

function encodePng(size, rgba) {
  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(size, 0);
  ihdr.writeUInt32BE(size, 4);
  ihdr[8] = 8;  // bit depth
  ihdr[9] = 6;  // RGBA
  const raw = Buffer.alloc(size * (size * 4 + 1));
  for (let y = 0; y < size; y++) {
    raw[y * (size * 4 + 1)] = 0; // filter: none
    rgba.copy(raw, y * (size * 4 + 1) + 1, y * size * 4, (y + 1) * size * 4);
  }
  return Buffer.concat([
    Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]),
    chunk('IHDR', ihdr),
    chunk('IDAT', deflateSync(raw)),
    chunk('IEND', Buffer.alloc(0)),
  ]);
}

// Signed distance-ish shield with a keyhole cutout.
function render(size) {
  const rgba = Buffer.alloc(size * size * 4);
  const cx = 0.5, topY = 0.08, botY = 0.95;
  for (let py = 0; py < size; py++) {
    for (let px = 0; px < size; px++) {
      const x = (px + 0.5) / size, y = (py + 0.5) / size;
      // Shield silhouette: rounded top rect tapering to a point at the bottom.
      let inside = false;
      if (y >= topY && y <= botY) {
        const t = (y - topY) / (botY - topY);
        // half-width narrows towards the bottom point
        const hw = t < 0.45 ? 0.38 : 0.38 * (1 - (t - 0.45) / 0.55) ** 0.8;
        inside = Math.abs(x - cx) <= hw;
      }
      // Keyhole cutout (white): circle + stem
      let hole = false;
      const dxk = x - cx, dyk = y - 0.40;
      if (dxk * dxk + dyk * dyk < 0.011) hole = true;
      if (Math.abs(dxk) < 0.045 && y >= 0.40 && y <= 0.62) hole = true;

      const i = (py * size + px) * 4;
      if (inside) {
        if (hole) {
          rgba[i] = 255; rgba[i + 1] = 255; rgba[i + 2] = 255; rgba[i + 3] = 255;
        } else {
          rgba[i] = 0xe0; rgba[i + 1] = 0x24; rgba[i + 2] = 0x24; rgba[i + 3] = 255;
        }
      } else {
        rgba[i + 3] = 0;
      }
    }
  }
  return rgba;
}

for (const size of [16, 48, 128]) {
  const png = encodePng(size, render(size));
  const file = join(OUT_DIR, `icon${size}.png`);
  writeFileSync(file, png);
  console.log(`wrote ${file} (${png.length} bytes)`);
}

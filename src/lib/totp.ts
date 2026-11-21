const BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

export interface TotpResult {
  code: string;
  formatted: string;
  remaining: number;
  period: number;
}

export interface TotpParams {
  secretBytes: Uint8Array;
  period: number;
  digits: number;
}

function decodeBase32(rawSecret: string): Uint8Array | null {
  const clean = rawSecret.replace(/[\s-]+/g, "").replace(/=+$/, "").toUpperCase();
  if (!clean) return null;

  const bytes: number[] = [];
  let buffer = 0;
  let bitsLeft = 0;

  for (let i = 0; i < clean.length; i += 1) {
    const val = BASE32_ALPHABET.indexOf(clean[i]);
    if (val === -1) return null;
    buffer = (buffer << 5) | val;
    bitsLeft += 5;
    if (bitsLeft >= 8) {
      bitsLeft -= 8;
      bytes.push((buffer >>> bitsLeft) & 0xff);
    }
  }

  return bytes.length > 0 ? new Uint8Array(bytes) : null;
}

function rotl(val: number, bits: number): number {
  return ((val << bits) | (val >>> (32 - bits))) >>> 0;
}

function sha1(message: Uint8Array): Uint8Array {
  const msgLen = message.length;
  const paddedLen = Math.ceil((msgLen + 9) / 64) * 64;
  const padded = new Uint8Array(paddedLen);
  padded.set(message, 0);
  padded[msgLen] = 0x80;

  const view = new DataView(padded.buffer);
  const bitLenHi = Math.floor((msgLen * 8) / 0x100000000);
  const bitLenLo = (msgLen * 8) >>> 0;
  view.setUint32(paddedLen - 8, bitLenHi, false);
  view.setUint32(paddedLen - 4, bitLenLo, false);

  let h0 = 0x67452301;
  let h1 = 0xefcdab89;
  let h2 = 0x98badcfe;
  let h3 = 0x10325476;
  let h4 = 0xc3d2e1f0;

  const w = new Uint32Array(80);

  for (let offset = 0; offset < paddedLen; offset += 64) {
    for (let i = 0; i < 16; i += 1) {
      w[i] = view.getUint32(offset + i * 4, false);
    }
    for (let i = 16; i < 80; i += 1) {
      w[i] = rotl(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);
    }

    let a = h0;
    let b = h1;
    let c = h2;
    let d = h3;
    let e = h4;

    for (let i = 0; i < 80; i += 1) {
      let f: number;
      let k: number;
      if (i < 20) {
        f = (b & c) | (~b & d);
        k = 0x5a827999;
      } else if (i < 40) {
        f = b ^ c ^ d;
        k = 0x6ed9eba1;
      } else if (i < 60) {
        f = (b & c) | (b & d) | (c & d);
        k = 0x8f1bbcdc;
      } else {
        f = b ^ c ^ d;
        k = 0xca62c1d6;
      }

      const temp = (rotl(a, 5) + (f >>> 0) + e + k + w[i]) >>> 0;
      e = d;
      d = c;
      c = rotl(b, 30);
      b = a;
      a = temp;
    }

    h0 = (h0 + a) >>> 0;
    h1 = (h1 + b) >>> 0;
    h2 = (h2 + c) >>> 0;
    h3 = (h3 + d) >>> 0;
    h4 = (h4 + e) >>> 0;
  }

  const out = new Uint8Array(20);
  const outView = new DataView(out.buffer);
  outView.setUint32(0, h0, false);
  outView.setUint32(4, h1, false);
  outView.setUint32(8, h2, false);
  outView.setUint32(12, h3, false);
  outView.setUint32(16, h4, false);
  return out;
}

function hmacSha1(key: Uint8Array, message: Uint8Array): Uint8Array {
  const blockSize = 64;
  let normalizedKey = key;
  if (normalizedKey.length > blockSize) {
    normalizedKey = sha1(normalizedKey);
  }

  const keyBlock = new Uint8Array(blockSize);
  keyBlock.set(normalizedKey, 0);

  const inner = new Uint8Array(blockSize + message.length);
  const outer = new Uint8Array(blockSize + 20);

  for (let i = 0; i < blockSize; i += 1) {
    inner[i] = keyBlock[i] ^ 0x36;
    outer[i] = keyBlock[i] ^ 0x5c;
  }
  inner.set(message, blockSize);
  const innerHash = sha1(inner);
  outer.set(innerHash, blockSize);
  return sha1(outer);
}

/** Extract Base32 secret, period, and digit count from a raw TOTP key or `otpauth://` URI. */
export function extractTotpParams(input: string): TotpParams | null {
  const trimmed = input.trim();
  if (!trimmed) return null;

  let secretRaw = trimmed;
  let period = 30;
  let digits = 6;

  if (trimmed.toLowerCase().startsWith("otpauth://")) {
    try {
      const url = new URL(trimmed);
      const alg = (url.searchParams.get("algorithm") || "SHA1").toUpperCase();
      if (alg !== "SHA1") return null;

      const s = url.searchParams.get("secret");
      if (!s) return null;
      secretRaw = s;

      const p = Number.parseInt(url.searchParams.get("period") || "30", 10);
      if (Number.isFinite(p) && p > 0 && p <= 300) {
        period = p;
      }

      const d = Number.parseInt(url.searchParams.get("digits") || "6", 10);
      if (d === 6 || d === 8) {
        digits = d;
      }
    } catch {
      return null;
    }
  }

  const secretBytes = decodeBase32(secretRaw);
  if (!secretBytes) return null;

  return { secretBytes, period, digits };
}

/** Generate a synchronous offline RFC 6238 TOTP code from a raw Base32 secret or `otpauth://` URI. */
export function generateTotp(input: string, nowMs = Date.now()): TotpResult | null {
  const params = extractTotpParams(input);
  if (!params) return null;

  const epochSec = Math.floor(nowMs / 1000);
  const counter = Math.floor(epochSec / params.period);
  const remaining = params.period - (epochSec % params.period);

  const counterBytes = new Uint8Array(8);
  const counterView = new DataView(counterBytes.buffer);
  counterView.setUint32(0, Math.floor(counter / 0x100000000), false);
  counterView.setUint32(4, counter >>> 0, false);

  const digest = hmacSha1(params.secretBytes, counterBytes);
  const offset = digest[digest.length - 1] & 0x0f;
  const binCode =
    (((digest[offset] & 0x7f) << 24) |
      ((digest[offset + 1] & 0xff) << 16) |
      ((digest[offset + 2] & 0xff) << 8) |
      (digest[offset + 3] & 0xff)) >>>
    0;

  const otp = binCode % 10 ** params.digits;
  const code = String(otp).padStart(params.digits, "0");
  const formatted =
    params.digits === 6
      ? `${code.slice(0, 3)} ${code.slice(3)}`
      : params.digits === 8
        ? `${code.slice(0, 4)} ${code.slice(4)}`
        : code;

  return { code, formatted, remaining, period: params.period };
}

/** Generate a random strong password locally via Web Crypto `getRandomValues`. */
export function generateStrongPassword(length = 18): string {
  const upper = "ABCDEFGHJKLMNPQRSTUVWXYZ";
  const lower = "abcdefghijkmnopqrstuvwxyz";
  const digits = "23456789";
  const symbols = "!@#$%^&*-_=+";
  const all = upper + lower + digits + symbols;

  const randomIndex = (max: number) => {
    const buf = new Uint32Array(1);
    const limit = Math.floor(0x100000000 / max) * max;
    let val = 0;
    do {
      crypto.getRandomValues(buf);
      val = buf[0];
    } while (val >= limit);
    return val % max;
  };

  const chars = [
    upper[randomIndex(upper.length)],
    lower[randomIndex(lower.length)],
    digits[randomIndex(digits.length)],
    symbols[randomIndex(symbols.length)],
  ];

  for (let i = chars.length; i < length; i += 1) {
    chars.push(all[randomIndex(all.length)]);
  }

  for (let i = chars.length - 1; i > 0; i -= 1) {
    const j = randomIndex(i + 1);
    const tmp = chars[i];
    chars[i] = chars[j];
    chars[j] = tmp;
  }

  return chars.join("");
}

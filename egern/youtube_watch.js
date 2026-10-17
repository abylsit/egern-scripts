var __defProp = Object.defineProperty;
var __defNormalProp = (obj, key, value) => key in obj ? __defProp(obj, key, { enumerable: true, configurable: true, writable: true, value }) : obj[key] = value;
var __publicField = (obj, key, value) => __defNormalProp(obj, typeof key !== "symbol" ? key + "" : key, value);

// ../js-build/node_modules/@noble/ciphers/utils.js
function isBytes(a) {
  return a instanceof Uint8Array || ArrayBuffer.isView(a) && a.constructor.name === "Uint8Array" && "BYTES_PER_ELEMENT" in a && a.BYTES_PER_ELEMENT === 1;
}
var atitle = (title) => title ? `"${title}" ` : "";
function anumber(n, title = "") {
  if (typeof n !== "number")
    throw new TypeError(atitle(title) + "expected number, got " + typeof n);
  if (!Number.isSafeInteger(n) || n < 0)
    throw new RangeError(atitle(title) + "expected integer >= 0, got " + n);
  return n;
}
function abytes(value, length, title = "") {
  if (isBytes(value) && (length === void 0 || value.length === length))
    return value;
  if (length !== void 0)
    anumber(length, "length");
  const bytes = isBytes(value);
  const ofLen = length !== void 0 ? ` of length ${length}` : "";
  const got = bytes ? `length=${value.length}` : `type=${typeof value}`;
  const message = atitle(title) + "expected Uint8Array" + ofLen + ", got " + got;
  if (!bytes)
    throw new TypeError(message);
  throw new RangeError(message);
}
function u8(arr) {
  return new Uint8Array(arr.buffer, arr.byteOffset, arr.byteLength);
}
function u32(arr) {
  return new Uint32Array(arr.buffer, arr.byteOffset, Math.floor(arr.byteLength / 4));
}
function clean(...arrays) {
  for (let i = 0; i < arrays.length; i++) {
    arrays[i].fill(0);
  }
}
var isLE = /* @__PURE__ */ (() => new Uint8Array(new Uint32Array([287454020]).buffer)[0] === 68)();
function byteSwap(word) {
  return word << 24 & 4278190080 | word << 8 & 16711680 | word >>> 8 & 65280 | word >>> 24 & 255;
}
var swap8IfBE = isLE ? (n) => n : (n) => byteSwap(n) >>> 0;
function byteSwap32(arr) {
  for (let i = 0; i < arr.length; i++) {
    arr[i] = byteSwap(arr[i]);
  }
  return arr;
}
var swap32IfBE = isLE ? (u) => u : byteSwap32;
function overlapBytes(a, b) {
  if (!a.byteLength || !b.byteLength)
    return false;
  return a.buffer === b.buffer && // best we can do, may fail with an obscure Proxy
  a.byteOffset < b.byteOffset + b.byteLength && // a starts before b end
  b.byteOffset < a.byteOffset + a.byteLength;
}
function complexOverlapBytes(input, output) {
  if (overlapBytes(input, output) && input.byteOffset < output.byteOffset)
    throw new Error("complex overlap of input and output is not supported");
}
var wrapCipher = /* @__NO_SIDE_EFFECTS__ */ (params, constructor) => {
  function wrappedCipher(key, ...args) {
    abytes(key, void 0, "key");
    if (params.nonceLength !== void 0) {
      const nonce = args[0];
      abytes(nonce, params.varSizeNonce ? void 0 : params.nonceLength, "nonce");
    }
    const tagl = params.tagLength;
    const aadStart = params.nonceLength !== void 0 ? 1 : 0;
    if (!params.withAAD) {
      for (let i = aadStart; i < args.length; i++)
        if (isBytes(args[i]))
          throw new Error("AAD not supported");
    }
    if (params.withAAD && args[aadStart] !== void 0)
      abytes(args[aadStart], void 0, "AAD");
    const cipher = constructor(key, ...args);
    const checkOutput = (fnLength, output) => {
      if (output !== void 0) {
        if (fnLength !== 2)
          throw new Error("cipher output not supported");
        abytes(output, void 0, "output");
      }
    };
    let called = false;
    const wrCipher = {
      encrypt(data, output) {
        if (called)
          throw new Error("cannot encrypt() twice with same key + nonce");
        called = true;
        abytes(data, void 0, "data");
        checkOutput(cipher.encrypt.length, output);
        return cipher.encrypt(data, output);
      },
      decrypt(data, output) {
        abytes(data, void 0, "data");
        if (tagl && data.length < tagl)
          throw new Error('"ciphertext" expected length >= tagLength=' + tagl);
        checkOutput(cipher.decrypt.length, output);
        return cipher.decrypt(data, output);
      }
    };
    return wrCipher;
  }
  Object.assign(wrappedCipher, params);
  return wrappedCipher;
};
function getOutput(expectedLength, out, onlyAligned = true) {
  if (out === void 0)
    return new Uint8Array(expectedLength);
  abytes(out, expectedLength, "output");
  if (onlyAligned && !isAligned32(out))
    throw new Error("invalid output, must be aligned");
  return out;
}
function isAligned32(bytes) {
  return bytes.byteOffset % 4 === 0;
}
function copyBytes(bytes) {
  return Uint8Array.from(abytes(bytes));
}

// ../js-build/node_modules/@noble/ciphers/aes.js
var BLOCK_SIZE = 16;
var BLOCK_SIZE32 = 4;
var POLY = 283;
function validateKeyLength(key) {
  if (![16, 24, 32].includes(key.length))
    throw new Error('"aes key" expected Uint8Array of length 16/24/32, got length=' + key.length);
}
function mul2(n) {
  return n << 1 ^ POLY & -(n >> 7);
}
function mul(a, b) {
  let res = 0;
  for (; b > 0; b >>= 1) {
    res ^= a & -(b & 1);
    a = mul2(a);
  }
  return res;
}
var sbox = /* @__PURE__ */ (() => {
  const t = new Uint8Array(256);
  for (let i = 0, x = 1; i < 256; i++, x ^= mul2(x))
    t[i] = x;
  const box = new Uint8Array(256);
  box[0] = 99;
  for (let i = 0; i < 255; i++) {
    let x = t[255 - i];
    x |= x << 8;
    box[t[i]] = (x ^ x >> 4 ^ x >> 5 ^ x >> 6 ^ x >> 7 ^ 99) & 255;
  }
  clean(t);
  return box;
})();
var rotr32_8 = (n) => n << 24 | n >>> 8;
var rotl32_8 = (n) => n << 8 | n >>> 24;
function genTtable(sbox2, fn) {
  if (sbox2.length !== 256)
    throw new Error("wrong sbox length");
  const T0 = new Uint32Array(256).map((_, j) => fn(sbox2[j]));
  const T1 = T0.map(rotl32_8);
  const T2 = T1.map(rotl32_8);
  const T3 = T2.map(rotl32_8);
  const T01 = new Uint32Array(256 * 256);
  const T23 = new Uint32Array(256 * 256);
  const sbox22 = new Uint16Array(256 * 256);
  for (let i = 0; i < 256; i++) {
    for (let j = 0; j < 256; j++) {
      const idx = i * 256 + j;
      T01[idx] = T0[i] ^ T1[j];
      T23[idx] = T2[i] ^ T3[j];
      sbox22[idx] = sbox2[i] << 8 | sbox2[j];
    }
  }
  return { sbox: sbox2, sbox2: sbox22, T0, T1, T2, T3, T01, T23 };
}
var tableEncoding = /* @__PURE__ */ genTtable(sbox, (s) => mul(s, 3) << 24 | s << 16 | s << 8 | mul(s, 2));
var xPowers = /* @__PURE__ */ (() => {
  const p = new Uint8Array(16);
  for (let i = 0, x = 1; i < 16; i++, x = mul2(x))
    p[i] = x;
  return p;
})();
function expandKeyLE(key) {
  abytes(key);
  const len = key.length;
  validateKeyLength(key);
  const { sbox2 } = tableEncoding;
  const toClean = [];
  if (!isLE || !isAligned32(key))
    toClean.push(key = copyBytes(key));
  const k32 = swap32IfBE(u32(key));
  const Nk = k32.length;
  const subByte = (n) => applySbox(sbox2, n, n, n, n);
  const xk = new Uint32Array(len + 28);
  xk.set(k32);
  for (let i = Nk; i < xk.length; i++) {
    let t = xk[i - 1];
    if (i % Nk === 0)
      t = subByte(rotr32_8(t)) ^ xPowers[i / Nk - 1];
    else if (Nk > 6 && i % Nk === 4)
      t = subByte(t);
    xk[i] = xk[i - Nk] ^ t;
  }
  clean(...toClean);
  return xk;
}
function apply0123(T01, T23, s0, s1, s2, s3) {
  return T01[s0 << 8 & 65280 | s1 >>> 8 & 255] ^ T23[s2 >>> 8 & 65280 | s3 >>> 24 & 255];
}
function applySbox(sbox2, s0, s1, s2, s3) {
  return sbox2[s0 & 255 | s1 & 65280] | sbox2[s2 >>> 16 & 255 | s3 >>> 16 & 65280] << 16;
}
function encrypt(xk, s0, s1, s2, s3) {
  const { sbox2, T01, T23 } = tableEncoding;
  let k = 0;
  s0 ^= xk[k++], s1 ^= xk[k++], s2 ^= xk[k++], s3 ^= xk[k++];
  const rounds = xk.length / 4 - 2;
  for (let i = 0; i < rounds; i++) {
    const t02 = xk[k++] ^ apply0123(T01, T23, s0, s1, s2, s3);
    const t12 = xk[k++] ^ apply0123(T01, T23, s1, s2, s3, s0);
    const t22 = xk[k++] ^ apply0123(T01, T23, s2, s3, s0, s1);
    const t32 = xk[k++] ^ apply0123(T01, T23, s3, s0, s1, s2);
    s0 = t02, s1 = t12, s2 = t22, s3 = t32;
  }
  const t0 = xk[k++] ^ applySbox(sbox2, s0, s1, s2, s3);
  const t1 = xk[k++] ^ applySbox(sbox2, s1, s2, s3, s0);
  const t2 = xk[k++] ^ applySbox(sbox2, s2, s3, s0, s1);
  const t3 = xk[k++] ^ applySbox(sbox2, s3, s0, s1, s2);
  return { s0: t0, s1: t1, s2: t2, s3: t3 };
}
function ctrCounter(xk, nonce, src, dst) {
  abytes(nonce, BLOCK_SIZE, "nonce");
  abytes(src);
  const srcLen = src.length;
  dst = getOutput(srcLen, dst);
  complexOverlapBytes(src, dst);
  const ctr2 = nonce;
  const c32 = u32(ctr2);
  const src32 = u32(src);
  const dst32 = u32(dst);
  for (let i = 0; i + 4 <= src32.length; i += 4) {
    const { s0, s1, s2, s3 } = encrypt(xk, swap8IfBE(c32[0]), swap8IfBE(c32[1]), swap8IfBE(c32[2]), swap8IfBE(c32[3]));
    dst32[i + 0] = src32[i + 0] ^ swap8IfBE(s0);
    dst32[i + 1] = src32[i + 1] ^ swap8IfBE(s1);
    dst32[i + 2] = src32[i + 2] ^ swap8IfBE(s2);
    dst32[i + 3] = src32[i + 3] ^ swap8IfBE(s3);
    for (let j = BLOCK_SIZE - 1, carry = 1; j >= 0; j--) {
      carry = carry + ctr2[j] | 0;
      ctr2[j] = carry & 255;
      carry >>>= 8;
    }
  }
  const start = BLOCK_SIZE * Math.floor(src32.length / BLOCK_SIZE32);
  if (start < srcLen) {
    const { s0, s1, s2, s3 } = encrypt(xk, swap8IfBE(c32[0]), swap8IfBE(c32[1]), swap8IfBE(c32[2]), swap8IfBE(c32[3]));
    const b32 = new Uint32Array([s0, s1, s2, s3]);
    swap32IfBE(b32);
    const buf = u8(b32);
    for (let i = start, pos = 0; i < srcLen; i++, pos++)
      dst[i] = src[i] ^ buf[pos];
    clean(b32);
  }
  return dst;
}
var ctr = /* @__PURE__ */ wrapCipher({ blockSize: 16, nonceLength: 16 }, function aesctr(key, nonce) {
  function processCtr(buf, dst) {
    abytes(buf);
    if (dst !== void 0) {
      abytes(dst);
      if (!isAligned32(dst))
        throw new Error("unaligned destination");
    }
    const xk = expandKeyLE(key);
    const n = copyBytes(nonce);
    const toClean = [xk, n];
    if (!isAligned32(buf))
      toClean.push(buf = copyBytes(buf));
    const out = ctrCounter(xk, n, buf, dst);
    clean(...toClean);
    return out;
  }
  return {
    encrypt: (plaintext, dst) => processCtr(plaintext, dst),
    decrypt: (ciphertext, dst) => processCtr(ciphertext, dst)
  };
});

// ../js-build/node_modules/@noble/hashes/utils.js
function isBytes2(a) {
  return a instanceof Uint8Array || ArrayBuffer.isView(a) && a.constructor.name === "Uint8Array" && "BYTES_PER_ELEMENT" in a && a.BYTES_PER_ELEMENT === 1;
}
var atitle2 = (title) => title ? `"${title}" ` : "";
function anumber2(n, title = "") {
  if (typeof n !== "number")
    throw new TypeError(atitle2(title) + "expected number, got " + typeof n);
  if (!Number.isSafeInteger(n) || n < 0)
    throw new RangeError(atitle2(title) + "expected integer >= 0, got " + n);
  return n;
}
function abytes2(value, length, title = "") {
  if (isBytes2(value) && (length === void 0 || value.length === length))
    return value;
  if (length !== void 0)
    anumber2(length, "length");
  const bytes = isBytes2(value);
  const ofLen = length !== void 0 ? ` of length ${length}` : "";
  const got = bytes ? `length=${value.length}` : `type=${typeof value}`;
  const message = atitle2(title) + "expected Uint8Array" + ofLen + ", got " + got;
  if (!bytes)
    throw new TypeError(message);
  throw new RangeError(message);
}
function ahash(h) {
  if (typeof h !== "function" || typeof h.create !== "function")
    throw new TypeError("expected hash wrapped by utils.createHasher");
  anumber2(h.outputLen);
  anumber2(h.blockLen);
  if (h.outputLen < 1 || h.blockLen < 1)
    throw new Error("hash blockLen / outputLen must be >= 1");
}
var aobject = (value, label) => {
  if (value === null || typeof value !== "object" || Array.isArray(value))
    throw new TypeError((label === "object" ? "" : `"${label}" `) + "expected object, got type=" + typeof value);
};
var aopts = (value, label) => {
  aobject(value, label);
  const proto = Object.getPrototypeOf(value);
  if (proto !== Object.prototype && proto !== null)
    throw new TypeError(`"${label}" expected plain object`);
  if (Object.hasOwn(value, "__proto__"))
    throw new TypeError(`"${label}.__proto__" is not allowed`);
};
function aexists2(instance, checkFinished = true) {
  if (instance.destroyed)
    throw new Error("hash was destroyed");
  if (checkFinished && instance.finished)
    throw new Error("digest() was already called");
}
function aoutput(out, instance) {
  abytes2(out, void 0, "output");
  const min = instance.outputLen;
  if (!(out.length >= min)) {
    throw new RangeError('"output" expected length >= ' + min);
  }
}
function clean2(...arrays) {
  for (let i = 0; i < arrays.length; i++) {
    arrays[i].fill(0);
  }
}
function createView2(arr) {
  return new DataView(arr.buffer, arr.byteOffset, arr.byteLength);
}
function rotr(word, shift) {
  return word << 32 - shift | word >>> shift;
}
function checkOpts(defaults, opts, title = "opts") {
  aopts(defaults, "defaults");
  if (opts !== void 0)
    aopts(opts, title);
  const merged = Object.assign(/* @__PURE__ */ Object.create(null), defaults, opts);
  return merged;
}
function createHasher(hashCons, info = {}) {
  if (typeof hashCons !== "function")
    throw new TypeError('"hashCons" expected function, got type=' + typeof hashCons);
  info = checkOpts({}, info, "info");
  const hashC = (msg, opts) => hashCons(opts).update(msg).digest();
  const tmp = hashCons(void 0);
  hashC.outputLen = tmp.outputLen;
  hashC.blockLen = tmp.blockLen;
  hashC.canXOF = tmp.canXOF;
  hashC.create = (opts) => hashCons(opts);
  Object.assign(hashC, info);
  return Object.freeze(hashC);
}
var oidNist = (suffix) => ({
  // Current NIST hashAlgs suffixes used here fit in one DER subidentifier octet.
  // Larger suffix values would need base-128 OID encoding and a different length byte.
  oid: Uint8Array.from([6, 9, 96, 134, 72, 1, 101, 3, 4, 2, suffix])
});

// ../js-build/node_modules/@noble/hashes/hmac.js
var _HMAC = class {
  constructor(hash, key) {
    __publicField(this, "oHash");
    __publicField(this, "iHash");
    __publicField(this, "blockLen");
    __publicField(this, "outputLen");
    __publicField(this, "canXOF", false);
    __publicField(this, "finished", false);
    __publicField(this, "destroyed", false);
    ahash(hash);
    abytes2(key, void 0, "key");
    this.iHash = hash.create();
    if (typeof this.iHash.update !== "function")
      throw new Error("expected Hash instance");
    this.blockLen = this.iHash.blockLen;
    this.outputLen = this.iHash.outputLen;
    const blockLen = this.blockLen;
    const pad = new Uint8Array(blockLen);
    pad.set(key.length > blockLen ? hash.create().update(key).digest() : key);
    for (let i = 0; i < pad.length; i++)
      pad[i] ^= 54;
    this.iHash.update(pad);
    this.oHash = hash.create();
    for (let i = 0; i < pad.length; i++)
      pad[i] ^= 54 ^ 92;
    this.oHash.update(pad);
    clean2(pad);
  }
  update(buf) {
    aexists2(this);
    this.iHash.update(buf);
    return this;
  }
  digestInto(out) {
    aexists2(this);
    aoutput(out, this);
    this.finished = true;
    const buf = out.subarray(0, this.outputLen);
    this.iHash.digestInto(buf);
    this.oHash.update(buf);
    this.oHash.digestInto(buf);
    this.destroy();
  }
  digest() {
    const out = new Uint8Array(this.oHash.outputLen);
    this.digestInto(out);
    return out;
  }
  _cloneInto(to) {
    to || (to = Object.create(Object.getPrototypeOf(this), {}));
    const { oHash, iHash, finished, destroyed, blockLen, outputLen, canXOF } = this;
    to = to;
    to.finished = finished;
    to.destroyed = destroyed;
    to.blockLen = blockLen;
    to.outputLen = outputLen;
    to.canXOF = canXOF;
    to.oHash = oHash._cloneInto(to.oHash);
    to.iHash = iHash._cloneInto(to.iHash);
    return to;
  }
  clone() {
    return this._cloneInto();
  }
  destroy() {
    this.destroyed = true;
    this.oHash.destroy();
    this.iHash.destroy();
  }
};
var hmac = /* @__PURE__ */ (() => {
  const hmac_ = ((hash, key, message) => new _HMAC(hash, key).update(message).digest());
  hmac_.create = (hash, key) => new _HMAC(hash, key);
  return hmac_;
})();

// ../js-build/node_modules/@noble/hashes/_u64.js
var fromNumH = (n) => n / 2 ** 32 | 0;
var fromNumL = (n) => n >>> 0;
function setU64FromNum(view, byteOffset, n, isLE2) {
  const h = fromNumH(n);
  const l = fromNumL(n);
  view.setUint32(byteOffset, isLE2 ? l : h, isLE2);
  view.setUint32(byteOffset + 4, isLE2 ? h : l, isLE2);
}

// ../js-build/node_modules/@noble/hashes/_md.js
function Chi(a, b, c) {
  return a & b ^ ~a & c;
}
function Maj(a, b, c) {
  return a & b ^ a & c ^ b & c;
}
var HashMD = class {
  constructor(blockLen, outputLen, padOffset, isLE2) {
    __publicField(this, "blockLen");
    __publicField(this, "outputLen");
    __publicField(this, "canXOF", false);
    __publicField(this, "padOffset");
    __publicField(this, "isLE");
    // For partial updates less than block size
    __publicField(this, "buffer");
    __publicField(this, "view");
    __publicField(this, "finished", false);
    __publicField(this, "length", 0);
    __publicField(this, "pos", 0);
    __publicField(this, "destroyed", false);
    this.blockLen = blockLen;
    this.outputLen = outputLen;
    this.padOffset = padOffset;
    this.isLE = isLE2;
    this.buffer = new Uint8Array(blockLen);
    this.view = createView2(this.buffer);
  }
  update(data) {
    aexists2(this);
    abytes2(data);
    const { view, buffer, blockLen } = this;
    const len = data.length;
    let processed = false;
    for (let pos = 0; pos < len; ) {
      const take = Math.min(blockLen - this.pos, len - pos);
      if (take === blockLen) {
        const dataView = createView2(data);
        for (; blockLen <= len - pos; pos += blockLen)
          this.process(dataView, pos);
        processed = true;
        continue;
      }
      buffer.set(pos === 0 && take === len ? data : data.subarray(pos, pos + take), this.pos);
      this.pos += take;
      pos += take;
      if (this.pos === blockLen) {
        this.process(view, 0);
        this.pos = 0;
        processed = true;
      }
    }
    this.length += data.length;
    if (processed)
      this.roundClean();
    return this;
  }
  digestInto(out) {
    aexists2(this);
    aoutput(out, this);
    this.finished = true;
    const { buffer, view, blockLen, isLE: isLE2 } = this;
    let { pos } = this;
    buffer[pos++] = 128;
    buffer.fill(0, pos);
    if (this.padOffset > blockLen - pos) {
      this.process(view, 0);
      buffer.fill(0);
    }
    setU64FromNum(view, blockLen - 8, this.length * 8, isLE2);
    this.process(view, 0);
    this.roundClean();
    const oview = out === buffer ? view : createView2(out);
    const len = this.outputLen;
    const outLen = len / 4;
    const state = this.get();
    if (len % 4 || outLen > state.length)
      throw new Error("invalid outputLen");
    for (let i = 0; i < outLen; i++)
      oview.setUint32(4 * i, state[i], isLE2);
  }
  digest() {
    const { buffer, outputLen } = this;
    this.digestInto(buffer);
    const res = buffer.slice(0, outputLen);
    this.destroy();
    return res;
  }
  _cloneIntoMeta(to) {
    const { buffer, length, finished, destroyed, pos } = this;
    to.destroyed = destroyed;
    to.finished = finished;
    to.length = length;
    to.pos = pos;
    if (pos)
      to.buffer.set(buffer);
    return to;
  }
  clone() {
    return this._cloneInto();
  }
};
var SHA256_IV = /* @__PURE__ */ Uint32Array.from([
  1779033703,
  3144134277,
  1013904242,
  2773480762,
  1359893119,
  2600822924,
  528734635,
  1541459225
]);

// ../js-build/node_modules/@noble/hashes/sha2.js
var SHA256_K = /* @__PURE__ */ Uint32Array.from([
  1116352408,
  1899447441,
  3049323471,
  3921009573,
  961987163,
  1508970993,
  2453635748,
  2870763221,
  3624381080,
  310598401,
  607225278,
  1426881987,
  1925078388,
  2162078206,
  2614888103,
  3248222580,
  3835390401,
  4022224774,
  264347078,
  604807628,
  770255983,
  1249150122,
  1555081692,
  1996064986,
  2554220882,
  2821834349,
  2952996808,
  3210313671,
  3336571891,
  3584528711,
  113926993,
  338241895,
  666307205,
  773529912,
  1294757372,
  1396182291,
  1695183700,
  1986661051,
  2177026350,
  2456956037,
  2730485921,
  2820302411,
  3259730800,
  3345764771,
  3516065817,
  3600352804,
  4094571909,
  275423344,
  430227734,
  506948616,
  659060556,
  883997877,
  958139571,
  1322822218,
  1537002063,
  1747873779,
  1955562222,
  2024104815,
  2227730452,
  2361852424,
  2428436474,
  2756734187,
  3204031479,
  3329325298
]);
var SHA256_W = /* @__PURE__ */ new Uint32Array(64);
var SHA2_32B = class extends HashMD {
  constructor(outputLen, IV) {
    super(64, outputLen, 8, false);
    // We cannot use array here since array allows indexing by variable
    // which means optimizer/compiler cannot use registers.
    // Numeric initializers matter: starting the fields as `undefined` changes
    // V8's field representation and makes sha256 3x slower (measured).
    __publicField(this, "A", 0);
    __publicField(this, "B", 0);
    __publicField(this, "C", 0);
    __publicField(this, "D", 0);
    __publicField(this, "E", 0);
    __publicField(this, "F", 0);
    __publicField(this, "G", 0);
    __publicField(this, "H", 0);
    this.A = IV[0] | 0;
    this.B = IV[1] | 0;
    this.C = IV[2] | 0;
    this.D = IV[3] | 0;
    this.E = IV[4] | 0;
    this.F = IV[5] | 0;
    this.G = IV[6] | 0;
    this.H = IV[7] | 0;
  }
  get() {
    const { A, B, C, D, E, F, G, H } = this;
    return [A, B, C, D, E, F, G, H];
  }
  // prettier-ignore
  set(A, B, C, D, E, F, G, H) {
    this.A = A | 0;
    this.B = B | 0;
    this.C = C | 0;
    this.D = D | 0;
    this.E = E | 0;
    this.F = F | 0;
    this.G = G | 0;
    this.H = H | 0;
  }
  _cloneInto(to) {
    (to || (to = new this.constructor())).set(...this.get());
    return this._cloneIntoMeta(to);
  }
  process(view, offset) {
    for (let i = 0; i < 16; i++, offset += 4)
      SHA256_W[i] = view.getUint32(offset, false);
    for (let i = 16; i < 64; i++) {
      const W15 = SHA256_W[i - 15];
      const W2 = SHA256_W[i - 2];
      const s0 = rotr(W15, 7) ^ rotr(W15, 18) ^ W15 >>> 3;
      const s1 = rotr(W2, 17) ^ rotr(W2, 19) ^ W2 >>> 10;
      SHA256_W[i] = s1 + SHA256_W[i - 7] + s0 + SHA256_W[i - 16] | 0;
    }
    let { A, B, C, D, E, F, G, H } = this;
    for (let i = 0; i < 64; i++) {
      const sigma1 = rotr(E, 6) ^ rotr(E, 11) ^ rotr(E, 25);
      const T1 = H + sigma1 + Chi(E, F, G) + SHA256_K[i] + SHA256_W[i] | 0;
      const sigma0 = rotr(A, 2) ^ rotr(A, 13) ^ rotr(A, 22);
      const T2 = sigma0 + Maj(A, B, C) | 0;
      H = G;
      G = F;
      F = E;
      E = D + T1 | 0;
      D = C;
      C = B;
      B = A;
      A = T1 + T2 | 0;
    }
    A = A + this.A | 0;
    B = B + this.B | 0;
    C = C + this.C | 0;
    D = D + this.D | 0;
    E = E + this.E | 0;
    F = F + this.F | 0;
    G = G + this.G | 0;
    H = H + this.H | 0;
    this.set(A, B, C, D, E, F, G, H);
  }
  roundClean() {
    clean2(SHA256_W);
  }
  destroy() {
    this.destroyed = true;
    this.set(0, 0, 0, 0, 0, 0, 0, 0);
    clean2(this.buffer);
  }
};
var _SHA256 = class extends SHA2_32B {
  constructor() {
    super(32, SHA256_IV);
  }
};
var sha256 = /* @__PURE__ */ createHasher(
  () => new _SHA256(),
  /* @__PURE__ */ oidNist(1)
);

// egern/src/youtube_watch.mjs
var KEY = "youtube.watch.single.keys.v1";
var REFRESH = "youtube.watch.single.config.v1";
var decoder = { decode(b) {
  const parts = [];
  for (let i = 0; i < b.length; i += 8192) parts.push(String.fromCharCode(...b.subarray(i, i + 8192)));
  return parts.join("");
} };
var eq = (a, b) => a.length === b.length && a.every((v, i) => v === b[i]);
var hex = (b) => Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
var unhex = (s) => Uint8Array.from(s.match(/../g) || [], (x) => parseInt(x, 16));
function join(xs) {
  const b = new Uint8Array(xs.reduce((n, x) => n + x.length, 0));
  let p = 0;
  for (const x of xs) {
    b.set(x, p);
    p += x.length;
  }
  return b;
}
function vint(b, p) {
  let n = 0, m = 1;
  for (let i = 0; i < 10; i++) {
    if (p >= b.length) throw Error("varint");
    const c = b[p++];
    n += (c & 127) * m;
    if (c < 128) return [n, p];
    m *= 128;
  }
  throw Error("varint size");
}
function enc(n) {
  const a = [];
  do {
    const x = n % 128;
    n = Math.floor(n / 128);
    a.push(x | (n ? 128 : 0));
  } while (n);
  return Uint8Array.from(a);
}
function field(n, b) {
  return join([enc(n * 8 + 2), enc(b.length), b]);
}
function fields(b) {
  let p = 0;
  const out = [];
  while (p < b.length) {
    const start = p;
    let tag;
    [tag, p] = vint(b, p);
    if (!Number.isSafeInteger(tag)) throw Error("tag");
    const n = Math.floor(tag / 8), w = tag % 8;
    if (n < 1 || n >= 2 ** 29) throw Error("field");
    let s = p;
    if (w === 2) {
      let z;
      [z, p] = vint(b, p);
      if (!Number.isSafeInteger(z)) throw Error("length");
      s = p;
      p += z;
    } else if (w === 0) [, p] = vint(b, p);
    else if (w === 1 || w === 5) p += w === 1 ? 8 : 4;
    else throw Error("wire");
    if (p > b.length) throw Error("truncated");
    out.push({ n, w, body: b.subarray(s, p), raw: b.subarray(start, p) });
  }
  return out;
}
function at(b, path) {
  let xs = [b];
  for (const n of path) xs = xs.flatMap((x) => fields(x).filter((f) => f.n === n && f.w === 2).map((f) => f.body));
  return xs;
}
function one(b, p) {
  const x = at(b, p);
  if (x.length !== 1) throw Error("single field");
  return x[0];
}
function rewrite(b, path, fn) {
  if (!path.length) return fn(b);
  let changed = false;
  const out = fields(b).map((f) => {
    if (f.n !== path[0] || f.w !== 2) return f.raw;
    const x = rewrite(f.body, path.slice(1), fn);
    if (eq(x, f.body)) return f.raw;
    changed = true;
    return field(f.n, x);
  });
  return changed ? join(out) : b;
}
var layout = (x) => decoder.decode(one(x, [172660663, 2, 183314536, 1]));
var base = [7, 51779735, 1, 49399797, 1];
var sections = [...base, 50195462];
function filterNext(input) {
  const all = at(input, [...sections, 1, 153515154]);
  const template = all.find((x) => layout(x).startsWith("spacing_cell.eml-fe|"));
  const stats = { renderers_replaced: 0, videos_kept: 0, community_posts_replaced: 0, pagination_removed: 0 };
  if (!template) return { output: input, stats };
  function spacer(x) {
    let core = one(template, [172660663]);
    const id = one(x, [172660663, 2, 183314536, 6]);
    core = rewrite(core, [2, 183314536, 6], () => id);
    stats.renderers_replaced++;
    return join([field(172660663, core), ...fields(x).filter((f) => f.n === 5).map((f) => f.raw)]);
  }
  let output = rewrite(input, sections, (sec) => {
    if (!at(sec, [7]).some((x) => decoder.decode(x) === "related-items")) return sec;
    return rewrite(sec, [1, 153515154], (x) => {
      const name = layout(x);
      if (stats.videos_kept < 1 && name.startsWith("video_lockup_with_attachment.eml-fe|") && !decoder.decode(x).includes("pagead")) {
        stats.videos_kept++;
        return x;
      }
      if (name.startsWith("cell_divider.eml-fe|") || name.startsWith("spacing_cell.eml-fe|")) return x;
      if (stats.renderers_replaced >= 150) throw Error("card limit");
      return spacer(x);
    });
  });
  function post(x) {
    if (!["images_post_root_slim.eml-fe|", "options_post_root.eml-fe|", "post_root.eml-fe|"].some((p) => layout(x).startsWith(p))) return x;
    stats.community_posts_replaced++;
    return spacer(x);
  }
  for (const p of [[...sections, 1, 153515154], [...base, 51845067, 5, 57988071, 1, 153515154]]) output = rewrite(output, p, post);
  output = rewrite(output, [7, 51779735, 1, 49399797], (b) => join(fields(b).filter((f) => {
    if (f.n === 2 && f.w === 2 && at(f.body, [52047593, 1]).length) {
      stats.pagination_removed++;
      return false;
    }
    return true;
  }).map((f) => f.raw)));
  return { output, stats };
}
function umpRead(b, p) {
  if (p >= b.length) throw Error("UMP");
  const first = b[p++];
  let lead = 0;
  while (lead < 4 && first & 128 >> lead) lead++;
  const size = lead + 1;
  let shift = size === 5 ? 0 : 8 - size, n = size === 5 ? 0 : first & (1 << shift) - 1;
  for (let i = 1; i < size; i++) {
    if (p >= b.length) throw Error("UMP integer");
    n += b[p++] * 2 ** shift;
    shift += 8;
  }
  return [n, p];
}
function umpEnc(n) {
  for (let size = 1; size <= 4; size++) {
    if (n < 2 ** (7 * size)) {
      const shift = 8 - size, prefix = size > 1 ? (1 << size - 1) - 1 << 9 - size : 0;
      const a = [prefix | n % 2 ** shift];
      n = Math.floor(n / 2 ** shift);
      for (let i = 1; i < size; i++) {
        a.push(n % 256);
        n = Math.floor(n / 256);
      }
      return Uint8Array.from(a);
    }
  }
  return Uint8Array.from([240, n % 256, Math.floor(n / 256) % 256, Math.floor(n / 65536) % 256, Math.floor(n / 16777216) % 256]);
}
function umpParts(b) {
  let p = 0;
  const xs = [];
  while (p < b.length) {
    const start = p;
    let type, size;
    [type, p] = umpRead(b, p);
    [size, p] = umpRead(b, p);
    if (p + size > b.length) throw Error("incomplete UMP");
    xs.push({ type, body: b.subarray(p, p + size), start, end: p + size });
    p += size;
  }
  return xs;
}
function replace(b, changes) {
  return join(fields(b).map((f) => changes.has(f.n) ? field(f.n, changes.get(f.n)) : f.raw));
}
function decode(payload, keys2) {
  const encrypted = one(payload, [1]), sig = one(payload, [2]), iv = one(payload, [3]);
  const compression = fields(payload).find((f) => f.n === 4 && f.w === 0);
  if (!compression || vint(compression.body, 0)[0] !== 1 || iv.length !== 16) return null;
  for (const key of keys2) {
    if (key.length !== 32) continue;
    if (!eq(hmac(sha256, key.subarray(16), join([encrypted, iv])), sig)) continue;
    return { compressed: ctr(key.subarray(0, 16), iv).decrypt(encrypted), key, iv };
  }
  return null;
}
async function transformUMP(input, keys2, compress) {
  const parts = umpParts(input), output = [];
  let header = null;
  const stats = { next_parts: 0, repacked_parts: 0, renderers_replaced: 0, videos_kept: 0, community_posts_replaced: 0, pagination_removed: 0 };
  for (const p of parts) {
    let raw = input.subarray(p.start, p.end);
    if (p.type === 10) {
      const t = fields(p.body).find((f) => f.n === 1 && f.w === 0);
      header = t ? vint(t.body, 0)[0] : null;
    } else if (p.type === 11) {
      const prior = header;
      header = null;
      if (prior === 25) {
        const d = decode(p.body, keys2);
        if (d) {
          const clear = await compress.gunzip(d.compressed);
          if (!clear) throw Error("gunzip");
          if (at(clear, [4, 3]).length) {
            stats.next_parts++;
            let edited = clear;
            if (!stats.renderers_replaced) edited = rewrite(clear, [4, 3], (next) => {
              if (stats.renderers_replaced) return next;
              const r = filterNext(next);
              for (const k of Object.keys(r.stats)) stats[k] += r.stats[k];
              return r.output;
            });
            const zipped = await compress.gzip(edited);
            if (!zipped) throw Error("gzip");
            const encrypted = ctr(d.key.subarray(0, 16), d.iv).encrypt(zipped), sig = hmac(sha256, d.key.subarray(16), join([encrypted, d.iv]));
            const body = replace(p.body, /* @__PURE__ */ new Map([[1, encrypted], [2, sig]]));
            raw = join([umpEnc(p.type), umpEnc(body.length), body]);
            stats.repacked_parts++;
          }
        }
      }
    }
    output.push(raw);
  }
  return { output: join(output), stats };
}
function keys(ctx) {
  return (ctx.storage.getJSON(KEY) || []).map(unhex);
}
function saveConfig(ctx, b) {
  let saved = false;
  for (const c of at(b, [1, 16, 7, 138536474, 146311580])) {
    for (const key of at(c, [1])) {
      if (key.length !== 32) continue;
      const ring = ctx.storage.getJSON(KEY) || [], s = hex(key);
      if (!ring.includes(s)) ring.push(s);
      ctx.storage.setJSON(KEY, ring.slice(-8));
      ctx.storage.set(REFRESH, "yes");
      saved = true;
    }
  }
  return saved;
}
var BUILD = "watch-one-v1";
async function report(ctx, stage, data = {}) {
  const url = ctx.env?.DEBUG_URL;
  if (!url) return;
  try {
    const throttle = "youtube.watch.diag." + BUILD + "." + stage + "." + (data.endpoint || "");
    if (Date.now() - Number(ctx.storage.get(throttle) || 0) < 3e3) return;
    ctx.storage.set(throttle, String(Date.now()));
    await ctx.http.post(url, { body: { build: BUILD, stage, ...data }, timeout: 1200, policy: "DIRECT", credentials: "omit" });
  } catch {
  }
}
async function youtube_watch_default(ctx) {
  const match = /^https:\/\/([^/:?#]+)(?::\d+)?(\/[^?#]*)/.exec(ctx.request.url);
  if (!match) return;
  const u = { hostname: match[1].toLowerCase() }, path = match[2];
  await report(ctx, ctx.response ? "response-entry" : "request-entry", { endpoint: path, status: ctx.response?.status, compression_api: !!ctx.compress });
  const config = u.hostname === "youtubei.googleapis.com" && ["/youtubei/v1/log_event", "/youtubei/v1/config"].includes(path);
  if (!ctx.response) {
    if (config && path.endsWith("/log_event") && !ctx.storage.get(REFRESH)) {
      ctx.request.headers.delete("x-youtube-hot-hash-data");
      await report(ctx, "config-refresh-requested");
      return { headers: ctx.request.headers };
    }
    return;
  }
  const init = u.hostname.endsWith(".googlevideo.com") && path === "/initplayback";
  const direct = u.hostname === "youtubei.googleapis.com" && path === "/youtubei/v1/next";
  if (!config && !init && !direct) return;
  let original;
  try {
    original = new Uint8Array(await ctx.response.arrayBuffer());
    if (config) {
      let saved = false;
      try {
        saved = saveConfig(ctx, original);
      } catch {
      }
      if (!saved) {
        const enc2 = ctx.response.headers.get("content-encoding");
        let plain;
        if (enc2 === "br") plain = await ctx.compress.unbrotli(original);
        else if (enc2 === "gzip") plain = await ctx.compress.gunzip(original);
        if (plain) saved = saveConfig(ctx, plain);
      }
      if (saved) {
        console.log("YT Watch: config key saved locally");
        await report(ctx, "config-saved", { key_count: keys(ctx).length });
      } else await report(ctx, "config-without-key", { bytes: original.length, encoding: ctx.response.headers.get("content-encoding") });
      return { body: original };
    }
    if (ctx.response.status !== 200) return { body: original };
    if (direct) {
      const r2 = filterNext(original);
      console.log("YT Watch direct " + JSON.stringify(r2.stats));
      await report(ctx, "direct-next-result", { bytes: original.length, ...r2.stats });
      if (eq(r2.output, original)) return { body: original };
      const headers2 = ctx.response.headers;
      headers2.delete("etag");
      headers2.delete("content-md5");
      headers2.delete("transfer-encoding");
      headers2.set("content-length", String(r2.output.length));
      return { headers: headers2, body: r2.output };
    }
    const ring = keys(ctx);
    if (!ring.length) {
      console.log("YT Watch: waiting for config key");
      await report(ctx, "waiting-config", { bytes: original.length });
      return { body: original };
    }
    const r = await transformUMP(original, ring, ctx.compress);
    console.log("YT Watch " + JSON.stringify(r.stats));
    await report(ctx, "filter-result", { bytes: original.length, key_count: ring.length, ...r.stats });
    if (!r.stats.repacked_parts) return { body: original };
    const headers = ctx.response.headers;
    headers.delete("etag");
    headers.delete("content-md5");
    headers.delete("transfer-encoding");
    headers.set("content-length", String(r.output.length));
    return { headers, body: r.output };
  } catch (e) {
    console.log("YT Watch: pass through (" + String(e) + ")");
    await report(ctx, "pass-through-error", { error: String(e).slice(0, 180) });
    if (original) return { body: original };
  }
}
export {
  youtube_watch_default as default,
  fields,
  filterNext,
  transformUMP
};
/*! Bundled license information:

@noble/ciphers/utils.js:
  (*! noble-ciphers - MIT License (c) 2023 Paul Miller (paulmillr.com) *)
*/

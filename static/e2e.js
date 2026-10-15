// Browser-side encryption for transfer.lyr4.net.
//
// A key is typed as CODE#SECRET. Only CODE reaches the server; SECRET stays in
// the browser. Each upload gets its own AES-GCM key, derived from SECRET and the
// upload id, and a share link carries that upload key after '#' — never SECRET.
//
// On disk each encrypted chunk is iv(12) || ciphertext || tag(16). The AAD binds
// a chunk to its file index, chunk index and chunk count, so the server cannot
// reorder, swap or truncate chunks without decryption failing.
(function () {
  const CHUNK_SIZE = 50 * 1024 * 1024;   // plaintext bytes per chunk
  const OVERHEAD = 12 + 16;              // iv + GCM tag
  const enc = new TextEncoder();
  const dec = new TextDecoder();

  function b64u(bytes) {
    let s = '';
    for (const b of new Uint8Array(bytes)) s += String.fromCharCode(b);
    return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  }

  function unb64u(text) {
    const s = atob(text.replace(/-/g, '+').replace(/_/g, '/'));
    return Uint8Array.from(s, c => c.charCodeAt(0));
  }

  function splitKey(typed) {
    const i = typed.indexOf('#');
    if (i < 0) return { code: typed.trim(), secret: '' };
    return { code: typed.slice(0, i).trim(), secret: typed.slice(i + 1).trim() };
  }

  async function uploadKeyBytes(secret, uploadId) {
    const ikm = await crypto.subtle.importKey('raw', enc.encode(secret), 'HKDF', false, ['deriveBits']);
    return new Uint8Array(await crypto.subtle.deriveBits(
      { name: 'HKDF', hash: 'SHA-256', salt: enc.encode('transfer.lyr4.net v1'), info: enc.encode('upload:' + uploadId) },
      ikm, 256));
  }

  function aesKey(raw) {
    return crypto.subtle.importKey('raw', raw, 'AES-GCM', false, ['encrypt', 'decrypt']);
  }

  async function seal(key, plain, aad) {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv, additionalData: enc.encode(aad) }, key, plain);
    const out = new Uint8Array(12 + ct.byteLength);
    out.set(iv); out.set(new Uint8Array(ct), 12);
    return out;
  }

  async function open(key, sealed, aad) {
    sealed = new Uint8Array(sealed);
    return crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: sealed.slice(0, 12), additionalData: enc.encode(aad) }, key, sealed.slice(12));
  }

  const chunkAad = (fileIndex, chunkIndex, chunkTotal) => `${fileIndex}:${chunkIndex}:${chunkTotal}`;
  const nameAad = fileIndex => `name:${fileIndex}`;

  async function sealName(key, fileIndex, name) {
    return b64u(await seal(key, enc.encode(name), nameAad(fileIndex)));
  }

  async function openName(key, fileIndex, nameEnc) {
    return dec.decode(await open(key, unb64u(nameEnc), nameAad(fileIndex)));
  }

  // Chunk count and plaintext size, recovered from the stored ciphertext size.
  function layout(cipherSize) {
    const total = Math.max(1, Math.ceil(cipherSize / (CHUNK_SIZE + OVERHEAD)));
    return { total, plainSize: cipherSize - total * OVERHEAD, stride: CHUNK_SIZE + OVERHEAD };
  }

  globalThis.E2E = {
    CHUNK_SIZE, OVERHEAD, b64u, unb64u, splitKey, uploadKeyBytes, aesKey,
    seal, open, chunkAad, sealName, openName, layout,
  };
})();

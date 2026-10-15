// Round trip against a running server: node tests/e2e_roundtrip.mjs <base-url> <CODE#SECRET>
import { readFileSync, readdirSync } from 'node:fs';
import { createHash, randomBytes } from 'node:crypto';
await import(new URL('../static/e2e.js', import.meta.url));
const { E2E } = globalThis;
const [base, fullKey] = process.argv.slice(2);
const { code, secret } = E2E.splitKey(fullKey);
const sha = b => createHash('sha256').update(Buffer.from(b)).digest('hex').slice(0, 16);

const files = [
  { name: 'small note.txt', data: Buffer.from('MARKER-PLAINTEXT hello from the test') },
  { name: 'big.bin', data: Buffer.concat([Buffer.from('MARKER-PLAINTEXT'), randomBytes(60 * 1024 * 1024)]) },
];
const uploadId = crypto.randomUUID();
const keyBytes = await E2E.uploadKeyBytes(secret, uploadId);
const key = await E2E.aesKey(keyBytes);
const finished = [];
for (const [fi, f] of files.entries()) {
  const total = Math.max(1, Math.ceil(f.data.length / E2E.CHUNK_SIZE));
  for (let ci = 0; ci < total; ci++) {
    const plain = f.data.subarray(ci * E2E.CHUNK_SIZE, (ci + 1) * E2E.CHUNK_SIZE);
    const fd = new FormData();
    for (const [k, v] of Object.entries({ auth_code: code, upload_id: uploadId, file_index: fi, chunk_index: ci, chunk_total: total, filename: `f${fi}` }))
      fd.append(k, String(v));
    fd.append('chunk', new Blob([await E2E.seal(key, plain, E2E.chunkAad(fi, ci, total))]), 'blob');
    const r = await (await fetch(`${base}/upload/chunk`, { method: 'POST', body: fd })).json();
    if (r.error) throw new Error(r.error);
    if (r.done) finished.push({ filename: r.filename, index: fi, name_enc: await E2E.sealName(key, fi, f.name), size: 1 });
  }
}
const fin = await (await fetch(`${base}/upload/finalize`, { method: 'POST', headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ auth_code: code, upload_id: uploadId, files: finished, encrypted: true }) })).json();
if (fin.error) throw new Error(fin.error);
console.log('uploaded', uploadId, 'share key', E2E.b64u(keyBytes));

const meta = JSON.parse(readFileSync(`metadata/${uploadId}.json`));
console.log('server-recorded sizes', meta.files.map(f => f.size), '(client claimed 1)');
const onDisk = readdirSync(`uploads/${uploadId}`).map(n => readFileSync(`uploads/${uploadId}/${n}`));
console.log('plaintext marker on disk:', onDisk.some(b => b.includes('MARKER-PLAINTEXT')),
            '| names on disk:', readdirSync(`uploads/${uploadId}`).join(','), '| name in metadata:', JSON.stringify(meta).includes('small note'));

// Download exactly as the landing page does
const shareKey = await E2E.aesKey(E2E.unb64u(E2E.b64u(keyBytes)));
for (const f of meta.files) {
  const name = await E2E.openName(shareKey, f.index, f.name_enc);
  const { total, stride, plainSize } = E2E.layout(f.size);
  const parts = [];
  for (let ci = 0; ci < total; ci++) {
    const end = Math.min((ci + 1) * stride, f.size) - 1;
    const res = await fetch(`${base}/dl/${uploadId}/${f.filename}`, { headers: { Range: `bytes=${ci * stride}-${end}` } });
    parts.push(Buffer.from(await E2E.open(shareKey, await res.arrayBuffer(), E2E.chunkAad(f.index, ci, total))));
  }
  const got = Buffer.concat(parts), want = files[f.index].data;
  console.log(`download ${name}: ${total} chunk(s), plainSize ${plainSize}, match=${sha(got) === sha(want) && plainSize === want.length}`);
}

// Tamper: ask for file 1's chunk 1 but claim it is chunk 0
const f1 = meta.files[1], { stride, total } = E2E.layout(f1.size);
const res = await fetch(`${base}/dl/${uploadId}/${f1.filename}`, { headers: { Range: `bytes=${stride}-${f1.size - 1}` } });
try { await E2E.open(shareKey, await res.arrayBuffer(), E2E.chunkAad(1, 0, total)); console.log('reordered chunk: ACCEPTED (bad)'); }
catch (e) { console.log('reordered chunk: rejected'); }
// Wrong secret cannot read the name
const wrong = await E2E.aesKey(await E2E.uploadKeyBytes(secret + 'x', uploadId));
try { await E2E.openName(wrong, 0, meta.files[0].name_enc); console.log('wrong secret: ACCEPTED (bad)'); }
catch (e) { console.log('wrong secret: rejected'); }

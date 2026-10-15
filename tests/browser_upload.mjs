// Drives a real headless Chrome through the upload page with a throwaway key:
//   node tests/browser_upload.mjs <base-url> <CODE#SECRET> [--no-login | --cancel | --stall | --resume]
// default    log in, upload a generated file, check it lands on My uploads and decrypts
// --no-login upload without logging in first; the page should log in with the key
// --cancel   throttle the upload, cancel it midway, report what the page shows
// --stall    hold one chunk request forever; the page should abandon and resend it
// --resume   throttle, abandon the upload partway as a closed tab would, reload,
//            choose the same file again and count the chunks the second run sends
import { spawn } from 'node:child_process';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const [base, fullKey, flag] = process.argv.slice(2);
const [code, secret] = fullKey.split('#');
const MB = 1024 * 1024;
const fileMB = flag === '--resume' ? 100 : 40;
const profile = mkdtempSync(join(tmpdir(), 'transfer-chrome-'));
const chrome = spawn('google-chrome', ['--headless=new', '--disable-gpu', '--no-sandbox', `--user-data-dir=${profile}`,
  '--remote-debugging-port=9333', 'about:blank'], { stdio: 'ignore' });
const sleep = ms => new Promise(r => setTimeout(r, ms));

try {
  let target;
  for (let i = 0; i < 50 && !target; i++) {
    await sleep(200);
    try { target = (await (await fetch('http://127.0.0.1:9333/json')).json()).find(t => t.type === 'page'); } catch {}
  }
  const ws = new WebSocket(target.webSocketDebuggerUrl);
  await new Promise(r => ws.addEventListener('open', r, { once: true }));
  let id = 0; const pending = new Map(); const listeners = [];
  ws.addEventListener('message', ev => {
    const m = JSON.parse(ev.data);
    if (m.id) { pending.get(m.id)?.(m); pending.delete(m.id); }
    else for (const l of listeners) l(m);
  });
  const send = (method, params = {}) => new Promise(r => { pending.set(++id, r); ws.send(JSON.stringify({ id, method, params })); });
  const evaluate = async expr => (await send('Runtime.evaluate', { expression: expr, awaitPromise: true, returnByValue: true })).result?.result?.value;
  const go = async url => { await send('Page.navigate', { url }); await sleep(1500); };
  const text = elId => evaluate(`document.getElementById('${elId}').textContent`);
  const throttle = bytesPerSec => send('Network.emulateNetworkConditions',
    { offline: false, latency: 20, downloadThroughput: -1, uploadThroughput: bytesPerSec });
  // The same bytes, name and timestamp every time, so a resume run picks "the same file"
  const pickFile = () => evaluate(`(() => {
    const body = new Uint8Array(${fileMB} * ${MB});
    for (let i = 0; i < body.length; i++) body[i] = i % 251;
    const dt = new DataTransfer();
    dt.items.add(new File([body], 'browser test.bin', { lastModified: 1700000000000 }));
    document.getElementById('file-input').files = dt.files;
  })()`);
  const waitForFiles = async () => {
    for (let i = 0; i < 240 && !(await evaluate('location.pathname')).startsWith('/files'); i++) await sleep(250);
  };
  let chunkRequests = 0;
  listeners.push(m => {
    if (m.method === 'Network.requestWillBeSent' && m.params.request.url.endsWith('/upload/chunk')) chunkRequests++;
  });
  await send('Network.enable');

  if (flag !== '--no-login') await go(`${base}/files/${code}#${secret}`);
  await go(`${base}/upload`);
  if (flag === '--no-login') await evaluate(`document.getElementById('auth_code').value = ${JSON.stringify(fullKey)}`);
  else console.log('key prefilled with secret:', await evaluate(`document.getElementById('auth_code').value === ${JSON.stringify(fullKey)}`));
  await pickFile();

  if (flag === '--cancel') {
    await throttle(2 * MB);
    send('Runtime.evaluate', { expression: 'startUpload()' });
    await sleep(3000);
    console.log('vault line:', await text('progress-vault'));
    console.log('progress line:', await text('progress-label'));
    console.log('progress before cancel:', await text('progress-detail'));
    if (process.env.SHOT) {
      const { data } = (await send('Page.captureScreenshot', { format: 'png' })).result;
      writeFileSync(process.env.SHOT, Buffer.from(data, 'base64'));
    }
    await evaluate('cancelUpload()');
    console.log('page after cancel:', await text('error-box'));
    process.exit(0);
  }

  if (flag === '--stall') {
    // Hold the first chunk request forever; let every other request through
    let held = 0;
    listeners.push(m => {
      if (m.method !== 'Fetch.requestPaused') return;
      if (held++ === 0) return;
      send('Fetch.continueRequest', { requestId: m.params.requestId });
    });
    await send('Fetch.enable', { patterns: [{ urlPattern: '*/upload/chunk', requestStage: 'Request' }] });
    await evaluate('STALL_MS = 4000');
    const t0 = Date.now();
    send('Runtime.evaluate', { expression: 'startUpload()' });
    await waitForFiles();
    console.log(`held one chunk; upload still finished in ${((Date.now() - t0) / 1000).toFixed(1)} s with ${chunkRequests} chunk requests for 3 chunks`);
  }

  if (flag === '--resume') {
    await throttle(4 * MB);
    send('Runtime.evaluate', { expression: 'startUpload()' });
    await sleep(18000);   // four chunks share 4 MB/s, so the first four finish at about 16 s
    console.log('abandoned at:', await text('progress-detail'));
    await evaluate('current = null');                 // as if the tab were closed
    await go(`${base}/upload`);                       // still throttled, so nothing in flight completes
    await throttle(-1);
    await pickFile();
    const before = chunkRequests;
    send('Runtime.evaluate', { expression: 'startUpload()' });
    await waitForFiles();
    console.log(`second run sent ${chunkRequests - before} of ${Math.ceil(fileMB * MB / (16 * MB))} chunks`);
  }

  if (!flag || flag === '--no-login') {
    send('Runtime.evaluate', { expression: 'startUpload()' });
    await waitForFiles();
  }

  console.log('landed on:', await evaluate('location.href'));
  console.log('My uploads lists:', await evaluate(`[...document.querySelectorAll('a.upload-row .file-name')].map(e => e.textContent)`));
  console.log('key status:', await evaluate(`document.getElementById('key-ok').style.display === 'block' ? 'loaded' : 'missing'`));
  const share = await evaluate(`document.querySelector('a.upload-row').href`);
  console.log('share link carries a key:', share.includes('#'));
  console.log('upload id:', share.split('/').pop().split('#')[0]);
  await go(share);
  console.log('share page decrypts to:', await evaluate(`document.querySelector('[data-name-enc]')?.textContent`));
  ws.close();
} finally {
  chrome.kill();
  await sleep(300);
  rmSync(profile, { recursive: true, force: true });
}

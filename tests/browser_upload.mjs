// Drives a real Chrome through the upload page: node tests/browser_upload.mjs <base-url> <CODE#SECRET> [--no-login | --cancel]
// Logs in, uploads a generated 40 MB file (three chunks in flight) with the page's own script,
// and checks where it lands. --cancel cancels mid-upload instead and reports what the page shows.
import { spawn } from 'node:child_process';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const [base, fullKey, flag] = process.argv.slice(2);
const [code, secret] = fullKey.split('#');
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
  let id = 0; const pending = new Map();
  ws.addEventListener('message', ev => { const m = JSON.parse(ev.data); pending.get(m.id)?.(m); pending.delete(m.id); });
  const send = (method, params = {}) => new Promise(r => { pending.set(++id, r); ws.send(JSON.stringify({ id, method, params })); });
  const evaluate = async expr => (await send('Runtime.evaluate', { expression: expr, awaitPromise: true, returnByValue: true })).result?.result?.value;
  const go = async url => { await send('Page.navigate', { url }); await sleep(1500); };

  if (flag !== '--no-login') await go(`${base}/files/${code}#${secret}`);
  await go(`${base}/upload`);
  if (flag === '--no-login') await evaluate(`document.getElementById('auth_code').value = ${JSON.stringify(fullKey)}`);
  else console.log('key prefilled with secret:', await evaluate(`document.getElementById('auth_code').value === ${JSON.stringify(fullKey)}`));
  await evaluate(`(() => {
    const dt = new DataTransfer();
    const body = new Uint8Array(40 * 1024 * 1024); body.set(new TextEncoder().encode('hello from a real browser upload'));
    dt.items.add(new File([body], 'browser test.bin'));
    document.getElementById('file-input').files = dt.files;
  })()`);
  if (flag === '--cancel') {
    // Slow the upload to 2 MB/s so there is something in flight to cancel
    await send('Network.enable');
    await send('Network.emulateNetworkConditions', { offline: false, latency: 20,
      downloadThroughput: -1, uploadThroughput: 2 * 1024 * 1024 });
  }
  send('Runtime.evaluate', { expression: 'startUpload()' });
  if (flag === '--cancel') {
    await sleep(3000);
    console.log('vault line:', await evaluate(`document.getElementById('progress-vault').textContent`));
    console.log('progress line:', await evaluate(`document.getElementById('progress-label').textContent`));
    console.log('progress before cancel:', await evaluate(`document.getElementById('progress-detail').textContent`));
    if (process.env.SHOT) {
      const { data } = (await send('Page.captureScreenshot', { format: 'png' })).result;
      (await import('node:fs')).writeFileSync(process.env.SHOT, Buffer.from(data, 'base64'));
    }
    await evaluate('cancelUpload()');
    console.log('page after cancel:', await evaluate(`document.getElementById('error-box').textContent`));
    ws.close();
    process.exit(0);
  }
  for (let i = 0; i < 60 && !(await evaluate('location.pathname')).startsWith('/files'); i++) await sleep(250);
  const url = await evaluate('location.href');
  console.log('landed on:', url);
  const names = await evaluate(`[...document.querySelectorAll('a.upload-row .file-name')].map(e => e.textContent)`);
  console.log('My uploads lists:', names);
  console.log('key status:', await evaluate(`document.getElementById('key-ok').style.display === 'block' ? 'loaded' : 'missing'`));
  const share = await evaluate(`document.querySelector('a.upload-row').href`);
  console.log('share link carries a key:', share.includes('#'));
  await go(share);
  console.log('share page decrypts to:', await evaluate(`document.querySelector('[data-name-enc]')?.textContent`));
  ws.close();
} finally {
  chrome.kill();
  await sleep(300);
  rmSync(profile, { recursive: true, force: true });
}

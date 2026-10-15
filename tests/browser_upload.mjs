// Drives a real Chrome through the upload page: node tests/browser_upload.mjs <base-url> <CODE#SECRET> [--no-login]
// Logs in, uploads a generated file with the page's own script, and checks where it lands.
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
    dt.items.add(new File(['hello from a real browser upload'], 'browser test.txt', { type: 'text/plain' }));
    document.getElementById('file-input').files = dt.files;
  })()`);
  await evaluate('startUpload()');
  await sleep(2500);
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

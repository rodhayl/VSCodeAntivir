// Installed-editor GUI checks only. Never call product classes as a substitute for UI.
// This driver is Windows-only and fails closed when an editor control cannot be observed.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const http = require('node:http');
const { spawn, execFileSync } = require('node:child_process');
const { verify } = require('./verify-package');

const DASHBOARD_TITLE = 'FIG Security Dashboard';
const REQUIRED = [
  'installed_identity_lifecycle', 'restricted_state', 'restricted_scan', 'restricted_dashboard',
  'restricted_refusal_and_storage', 'trusted_state_after_reload', 'quarantine_cancel', 'review_cancel',
  'review_apply', 'review_undo', 'review_conflict', 'quarantine_capture', 'quarantine_reload',
  'quarantine_conflict', 'quarantine_restore', 'keyboard_navigation', 'repeated_reload',
];
const hash = bytes => crypto.createHash('sha256').update(bytes).digest('hex');
const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));
const visibleScript = `el => !!el && el.getClientRects().length > 0 && getComputedStyle(el).visibility !== 'hidden'`;
function classifyTrust(state) {
  if (!state || typeof state.editorText !== 'string') return 'unknown';
  const restricted = /You are in Restricted Mode/i.test(state.editorText);
  const trusted = /You trust (?:the authors of the files in )?this (?:folder|workspace)/i.test(state.editorText);
  if (restricted && !trusted && state.statusText === 'Restricted Mode') return 'restricted';
  // Absence of the status item alone is never affirmative evidence of trust.
  if (trusted && !restricted && state.statusText !== 'Restricted Mode') return 'trusted';
  return 'unknown';
}
function validWorkspaceScan(toast) {
  const match = /^FIG: (\d+) reported finding\(s\); (\d+) files scanned, (\d+) skipped, (\d+) error\(s\)\./.exec(toast || '');
  // The isolated restricted workspace contains exactly one inert flagged fixture.
  return !!match && Number(match[1]) > 0 && Number(match[2]) === 1 && Number(match[3]) === 0 && Number(match[4]) === 0;
}
function snapshotStore(directory) {
  const result = [];
  function walk(target, relative) {
    const stat = fs.lstatSync(target);
    assert(!stat.isSymbolicLink(), 'Unexpected link in disposable quarantine store');
    result.push({ path: relative, directory: stat.isDirectory(), mode: stat.mode,
      ...(stat.isFile() ? { bytes: stat.size, sha256: hash(fs.readFileSync(target)) } : {}) });
    if (stat.isDirectory()) for (const name of fs.readdirSync(target).sort()) walk(path.join(target, name), path.join(relative, name));
  }
  try { fs.lstatSync(directory); } catch (error) { if (error.code === 'ENOENT') return result; throw error; }
  walk(directory, '.'); return result;
}
function requireDialog(dialog, message, action) {
  assert(dialog && dialog.message.includes(message) && dialog.buttons.includes(action),
    `Required native dialog/action not observed: ${message} / ${action}`);
}
function exitCode(results) {
  return results.error || REQUIRED.some(id => !results.checks.some(c => c.id === id && c.status === 'PASS')) ? 1 : 0;
}
class Recorder {
  constructor(directory) {
    this.directory = directory;
    this.result = { schemaVersion: 4, campaign: 'INSTALLED_GUI_AUTOMATED_SUBSET', startedAt: new Date().toISOString(),
      status: 'RUNNING', checks: REQUIRED.map(id => ({ id, status: 'NOT_RUN' })), screenshots: [], observations: [],
      limits: ['This driver does not prove absent model traffic or automatic watchers, custom-rule suppression, Windows ACL security, power-loss durability, or broad accessibility. Those checks require separate evidence.',
        'Live LLM providers are NOT RUN. No model request or paid-provider fallback is performed.'] };
  }
  save() { fs.writeFileSync(path.join(this.directory, 'RESULT.json'), JSON.stringify(this.result, null, 2) + '\n'); }
  observe(id, value) { this.result.observations.push({ id, at: new Date().toISOString(), value }); this.save(); }
  check(id, passed, evidence) {
    assert(REQUIRED.includes(id), `Unknown check: ${id}`);
    const entry = this.result.checks.find(check => check.id === id);
    assert.equal(entry.status, 'NOT_RUN', `Duplicate check: ${id}`);
    Object.assign(entry, { status: passed === true ? 'PASS' : 'FAIL', at: new Date().toISOString(), evidence });
    this.save(); assert.equal(passed, true, `Acceptance check failed: ${id}`);
  }
  screenshot(id, bytes, state) {
    assert(state && typeof state === 'object', 'Screenshot needs an observed UI state');
    const digest = hash(bytes);
    assert(!this.result.screenshots.some(shot => shot.sha256 === digest), `Duplicate screenshot cannot prove a new transition: ${id}`);
    const file = `screenshots/${id}.png`;
    fs.mkdirSync(path.join(this.directory, 'screenshots'), { recursive: true });
    fs.writeFileSync(path.join(this.directory, file), bytes, { flag: 'wx' });
    this.result.screenshots.push({ id, file, sha256: digest, bytes: bytes.length, at: new Date().toISOString(), state }); this.save();
  }
}

function getPage(port, expectedWorkspace, timeout = 30000) {
  return until(async () => new Promise(resolve => {
    const request = http.get(`http://127.0.0.1:${port}/json`, response => {
      let data = ''; response.on('data', chunk => data += chunk);
      response.on('end', () => {
        try { const pages = JSON.parse(data).filter(t => t.type === 'page' && t.title?.includes(expectedWorkspace)); resolve(pages.length === 1 ? pages[0] : null); }
        catch { resolve(null); }
      });
    });
    request.setTimeout(2000, () => request.destroy()); request.on('error', () => resolve(null));
  }), `a unique editor page for ${expectedWorkspace}`, timeout);
}
async function until(read, description, timeout = 12000) {
  const deadline = Date.now() + timeout;
  do { const value = await read(); if (value) return value; await sleep(200); } while (Date.now() < deadline);
  throw new Error(`Timed out waiting for ${description}`);
}
class CdpClient {
  constructor(url) { this.url = url; this.nextId = 1; this.pending = new Map(); this.contexts = new Map(); this.attachedTargets = new Set(); }
  async connect() {
    this.ws = new WebSocket(this.url);
    await new Promise((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error('CDP connect timeout')), 10000);
      this.ws.onopen = () => { clearTimeout(timer); resolve(); };
      this.ws.onerror = () => { clearTimeout(timer); reject(new Error('CDP connection failed')); };
    });
    this.ws.onmessage = event => {
      const message = JSON.parse(event.data);
      if (message.id && this.pending.has(message.id)) {
        const { resolve, reject, timer } = this.pending.get(message.id); clearTimeout(timer); this.pending.delete(message.id);
        if (message.error) reject(new Error(JSON.stringify(message.error))); else resolve(message.result);
      } else if (message.method === 'Runtime.executionContextCreated') {
        const context = message.params.context;
        this.contexts.set(`${message.sessionId || ''}:${context.id}`, { contextId: context.id, sessionId: message.sessionId });
      } else if (message.method === 'Runtime.executionContextDestroyed') {
        this.contexts.delete(`${message.sessionId || ''}:${message.params.executionContextId}`);
      } else if (message.method === 'Runtime.executionContextsCleared') {
        for (const [key, context] of this.contexts) if (context.sessionId === message.sessionId) this.contexts.delete(key);
      }
    };
    this.ws.onclose = () => this.rejectPending('CDP closed');
    await this.call('Runtime.enable');
  }
  rejectPending(detail) { for (const { reject, timer } of this.pending.values()) { clearTimeout(timer); reject(new Error(detail)); } this.pending.clear(); }
  call(method, params = {}, sessionId) {
    return new Promise((resolve, reject) => {
      const id = this.nextId++;
      const timer = setTimeout(() => { this.pending.delete(id); reject(new Error(`CDP timeout: ${method}`)); }, 10000);
      this.pending.set(id, { resolve, reject, timer });
      this.ws.send(JSON.stringify({ id, method, params, ...(sessionId ? { sessionId } : {}) }));
    });
  }
  async evaluate(expression, context) {
    const response = await this.call('Runtime.evaluate', { expression, returnByValue: true,
      ...(context?.contextId ? { contextId: context.contextId } : {}) }, context?.sessionId);
    assert(!response.exceptionDetails, `Editor evaluation failed: ${JSON.stringify(response.exceptionDetails)}`);
    assert(response.result && !response.result.subtype?.includes('error'), 'Editor evaluation returned an error');
    return response.result.value;
  }
  async key(key, code, vk, modifiers = 0) {
    for (const type of ['rawKeyDown', 'keyUp']) await this.call('Input.dispatchKeyEvent', { type, key, code, windowsVirtualKeyCode: vk, modifiers });
  }
  async insert(text) { await this.call('Input.insertText', { text }); }
  async screenshot(recorder, id, state) {
    const shot = await this.call('Page.captureScreenshot', { format: 'png' }); assert(shot.data, 'Missing screenshot data');
    recorder.screenshot(id, Buffer.from(shot.data, 'base64'), state);
  }
  async command(title) {
    await this.evaluate(`(() => { (document.querySelector('.native-edit-context') || document.querySelector('.monaco-workbench'))?.focus(); })()`);
    await this.key('F1', 'F1', 112);
    await until(() => this.evaluate(`Array.from(document.querySelectorAll('.quick-input-widget input')).some(el => (${visibleScript})(el))`), 'Command Palette input');
    await this.key('a', 'KeyA', 65, 2); await this.insert(`> ${title}`);
    await until(() => this.evaluate(`Array.from(document.querySelectorAll('.quick-input-list .monaco-list-row')).filter(${visibleScript}).some(el => (el.querySelector('.label-name')?.textContent || el.textContent).trim() === ${JSON.stringify(title)})`), `exact command ${title}`);
    const selected = await this.evaluate(`(() => { const rows = Array.from(document.querySelectorAll('.quick-input-list .monaco-list-row')).filter(${visibleScript}); const row = rows.find(el => (el.querySelector('.label-name')?.textContent || el.textContent).trim() === ${JSON.stringify(title)}); if (!row) return false; row.click(); return true; })()`);
    assert.equal(selected, true, `Command not selected: ${title}`);
    await until(() => this.evaluate(`!Array.from(document.querySelectorAll('.quick-input-widget')).some(${visibleScript})`), `command palette dismissed after ${title}`);
  }
  async openFile(file) {
    await this.evaluate(`(() => { (document.querySelector('.native-edit-context') || document.querySelector('.monaco-workbench'))?.focus(); })()`);
    await this.key('p', 'KeyP', 80, 2);
    await until(() => this.evaluate(`Array.from(document.querySelectorAll('.quick-input-widget input')).some(${visibleScript})`), 'Quick Open');
    await this.key('a', 'KeyA', 65, 2); await this.insert(file);
    await until(() => this.evaluate(`Array.from(document.querySelectorAll('.quick-input-list .monaco-list-row')).filter(${visibleScript}).some(el => el.textContent.includes(${JSON.stringify(path.basename(file))}))`), 'target file in Quick Open');
    await this.key('Enter', 'Enter', 13);
    await until(() => this.evaluate(`Array.from(document.querySelectorAll('.tab.active')).some(el => el.textContent.includes(${JSON.stringify(path.basename(file))}))`), 'selected file active in editor');
    await sleep(500);
  }
  async dialog() {
    return this.evaluate(`(() => { const box = Array.from(document.querySelectorAll('.monaco-dialog-box')).find(${visibleScript}); return box ? { message: box.textContent.trim(), buttons: Array.from(box.querySelectorAll('button,.monaco-button')).filter(${visibleScript}).map(el => el.textContent.trim()) } : null; })()`);
  }
  async click(selector, label) {
    const clicked = await this.evaluate(`(() => { const candidates = Array.from(document.querySelectorAll(${JSON.stringify(selector)})).filter(${visibleScript}).filter(el => el.textContent.trim() === ${JSON.stringify(label)}); if (candidates.length !== 1) return false; candidates[0].click(); return true; })()`);
    assert.equal(clicked, true, `Unique visible UI action not found: ${label}`);
  }
  async toasts() { return this.evaluate(`Array.from(document.querySelectorAll('.notification-toast')).filter(${visibleScript}).map(el => el.textContent.trim())`); }
  async toast(text) { return until(async () => { const values = await this.toasts(); return values.find(value => value.includes(text)); }, `notification: ${text}`); }
  async trust() {
    await this.command('Workspaces: Manage Workspace Trust');
    return until(async () => {
      const state = await this.evaluate(`(() => { const editor = document.querySelector('.workspace-trust-editor') || Array.from(document.querySelectorAll('.workspace-trust-editor')).find(${visibleScript}); const status = document.getElementById('status.workspaceTrust'); return { editorText: editor?.textContent?.trim() || '', statusText: status?.textContent?.trim() || null }; })()`);
      return classifyTrust(state) !== 'unknown' ? state : null;
    }, 'determinate Workspace Trust state', 15000);
  }
  async webviewAction(id, buttonClass) {
    // Attach only frame targets belonging to this disposable editor. Never run product code.
    const { targetInfos } = await this.call('Target.getTargets');
    const frames = targetInfos.filter(target => target.type === 'iframe' && /vscode-webview:/.test(target.url));
    for (const target of frames) {
      if (this.attachedTargets.has(target.targetId)) continue;
      const { sessionId } = await this.call('Target.attachToTarget', { targetId: target.targetId, flatten: true });
      await this.call('Runtime.enable', {}, sessionId); this.attachedTargets.add(target.targetId);
    }
    await sleep(200);
    const expression = `(() => { if (!document.querySelector('h1')?.textContent.includes('Quarantine Manager')) return false; const rows = Array.from(document.querySelectorAll('tr[data-id]')).filter(el => el.getAttribute('data-id') === ${JSON.stringify(id)}); if (rows.length !== 1) return false; if (${JSON.stringify(buttonClass === undefined)}) return { id: rows[0].getAttribute('data-id'), text: rows[0].textContent.trim() }; const button = rows[0].querySelector(${JSON.stringify('button.' + buttonClass)}); if (!button || button.disabled) return false; button.click(); return true; })()`;
    for (const context of this.contexts.values()) {
      try { const observed = await this.evaluate(expression, context); if (observed) return observed; }
      catch (error) { if (!/context|frame|target/i.test(error.message)) throw error; }
    }
    throw new Error('Quarantine webview action not observable; requires native operator validation, never direct manager fallback');
  }
  close() { this.rejectPending('CDP closed by driver'); this.ws?.close(); }
}

async function runInstalledGuiAcceptance(options = {}) {
  const root = path.resolve(__dirname, '..'); const repo = path.dirname(root);
  const runDir = options.output || path.join(root, '.vscode-test', 'installed-gui-runs', `${new Date().toISOString().replace(/[:.]/g, '-')}-${crypto.randomUUID()}`);
  fs.mkdirSync(runDir, { recursive: false });
  const recorder = new Recorder(runDir); const results = recorder.result; recorder.save();
  let child; let cdp;
  async function closeEditor() {
    cdp?.close(); cdp = undefined;
    if (child && child.exitCode === null) {
      const owned = child;
      owned.kill();
      await until(() => owned.exitCode !== null || owned.signalCode !== null, 'owned disposable editor to stop', 15000);
    }
    child = undefined;
  }
  try {
    assert.equal(process.platform, 'win32', 'This driver requires the owner-authorized Windows native editor; cloud/headless checks are not GUI acceptance');
    const codeExe = options.codeExe || process.env.FIG_CODE_EXE || path.join(root, '.vscode-test', 'vscode-win32-x64-archive-1.141.0', 'Code.exe');
    let cli = path.join(path.dirname(codeExe), 'resources', 'app', 'out', 'cli.js');
    if (!fs.existsSync(cli)) {
      for (const entry of fs.readdirSync(path.dirname(codeExe))) {
        const candidate = path.join(path.dirname(codeExe), entry, 'resources', 'app', 'out', 'cli.js');
        if (fs.existsSync(candidate)) { cli = candidate; break; }
      }
    }
    assert(fs.existsSync(codeExe) && fs.existsSync(cli), 'A real VS Code executable and its CLI are required');
    const pkg = require('../package.json'); const vsix = options.vsix || path.join(root, `${pkg.name}-${pkg.version}.vsix`);
    const sha = execFileSync('git', ['rev-parse', 'HEAD'], { cwd: repo, encoding: 'utf8' }).trim();
    const dirty = execFileSync('git', ['status', '--porcelain', '--untracked-files=all'], { cwd: repo, encoding: 'utf8' }).trim();
    assert.equal(dirty, '', 'All tracked/untracked source changes must be resolved before native acceptance');
    const artifact = await verify(vsix);
    const metadata = JSON.parse(fs.readFileSync(path.join(root, 'out', 'build-metadata.json')));
    for (const input of metadata.files) {
      const full = path.resolve(root, input.path); assert(full.startsWith(root + path.sep), 'Unsafe metadata input path');
      assert.equal(hash(fs.readFileSync(full)), input.sha256, `Source/metadata mismatch: ${input.path}`);
    }
    assert.equal(artifact.sourceTreeSha256, metadata.sourceTreeSha256, 'VSIX differs from current packaged source');
    Object.assign(results, { candidateCommit: sha, platform: process.platform, arch: process.arch, node: process.version, artifact }); recorder.save();
    const extDir = path.join(runDir, 'extensions'); fs.mkdirSync(extDir);
    const cliProfile = path.join(runDir, 'cli-profile'); fs.mkdirSync(cliProfile);
    const cliHome = path.join(runDir, 'cli-home'); fs.mkdirSync(cliHome);
    const cliEnv = { ...process.env, HOME: cliHome, USERPROFILE: cliHome, ELECTRON_RUN_AS_NODE: '1' };
    const runCli = args => execFileSync(codeExe, [cli, '--extensions-dir', extDir, '--user-data-dir', cliProfile, ...args], { env: cliEnv, encoding: 'utf8', timeout: 60000 });
    results.editorVersion = runCli(['--version']).trim();
    recorder.observe('install', runCli(['--install-extension', vsix]));
    assert(runCli(['--list-extensions', '--show-versions']).split(/\r?\n/).includes(`${pkg.publisher}.${pkg.name}@${pkg.version}`));
    recorder.observe('uninstall', runCli(['--uninstall-extension', `${pkg.publisher}.${pkg.name}`]));
    assert(!runCli(['--list-extensions']).includes(`${pkg.publisher}.${pkg.name}`));
    recorder.observe('reinstall', runCli(['--install-extension', vsix]));
    const copies = fs.readdirSync(extDir).filter(name => name.startsWith(`${pkg.publisher}.${pkg.name}-`)); assert.equal(copies.length, 1);
    const installed = JSON.parse(fs.readFileSync(path.join(extDir, copies[0], 'out/build-metadata.json')));
    recorder.check('installed_identity_lifecycle', JSON.stringify(installed) === JSON.stringify(metadata), { installedFolder: copies[0], installedMetadata: installed });

    const title = command => { const item = pkg.contributes.commands.find(c => c.command === command); assert(item, `Missing command ${command}`); return item.title; };
    async function launch(name, port) {
      const workspaceName = `${name}-${crypto.randomUUID()}`;
      const workspace = path.join(runDir, workspaceName); fs.mkdirSync(workspace);
      const home = path.join(runDir, `${name}-home`); fs.mkdirSync(home);
      const profile = path.join(runDir, `${name}-profile`); fs.mkdirSync(profile);
      fs.mkdirSync(path.join(profile, 'User'));
      fs.writeFileSync(path.join(profile, 'User/settings.json'), JSON.stringify({
        'workbench.startupEditor': 'none', 'security.workspace.trust.enabled': true,
        'security.workspace.trust.emptyWindow': false, 'security.workspace.trust.startupPrompt': 'always',
        'security.workspace.trust.banner': 'always', 'task.allowAutomaticTasks': 'off',
        'fig.scanOnOpen': false, 'fig.scanOnSave': false, 'fig.realTimeWatching': false,
      }, null, 2));
      const launchEnv = { ...process.env, HOME: home, USERPROFILE: home }; delete launchEnv.ELECTRON_RUN_AS_NODE;
      const launchArgs = [workspace, `--extensions-dir=${extDir}`, `--user-data-dir=${profile}`, `--remote-debugging-port=${port}`, '--locale=en', '--new-window', '--skip-welcome', '--skip-release-notes'];
      const log = fs.openSync(path.join(runDir, `${name}-editor.log`), 'wx');
      recorder.observe(`${name}-prelaunch`, { storeAbsent: !fs.existsSync(path.join(home, '.fakeinterviewguard')), launchArgs });
      try { child = spawn(codeExe, launchArgs, { env: launchEnv, stdio: ['ignore', log, log] }); }
      finally { fs.closeSync(log); }
      child.on('error', error => recorder.observe(`${name}-launch-error`, String(error)));
      const page = await getPage(port, workspaceName); cdp = new CdpClient(page.webSocketDebuggerUrl); await cdp.connect();
      recorder.observe(`${name}-connected`, { title: page.title, storePresent: fs.existsSync(path.join(home, '.fakeinterviewguard')) });
      const startup = await until(() => cdp.dialog(), 'Workspace Trust startup dialog');
      requireDialog(startup, 'trust', "No, I don't trust the authors");
      await cdp.click('.monaco-dialog-box button,.monaco-dialog-box .monaco-button', "No, I don't trust the authors");
      await until(async () => !await cdp.dialog(), 'startup dialog dismissal');
      const state = await cdp.trust();
      recorder.observe('debug-trust-state', state);
      assert.equal(classifyTrust(state), 'restricted', 'Known Restricted Mode must be established explicitly');
      return { workspace, workspaceName, home, profile, port, launchEnv, launchArgs, state };
    }
    const restricted = await launch('restricted-workspace', 9231);
    recorder.check('restricted_state', classifyTrust(restricted.state) === 'restricted', restricted.state);
    await cdp.screenshot(recorder, '01-restricted-state', restricted.state);
    const sample = path.join(restricted.workspace, 'review.js'); fs.writeFileSync(sample, '// Inert fixture only: eval(\n');
    const original = hash(fs.readFileSync(sample));
    await cdp.command(title('fig.scanWorkspace'));
    const scanToast = await cdp.toast('reported finding(s)');
    assert(validWorkspaceScan(scanToast), 'Workspace scan did not inspect the inert fixture with findings and zero errors/skips');
    await cdp.openFile(sample); await cdp.command(title('fig.scanFile'));
    const fileScanToast = await cdp.toast('finding(s) in scanned file review.js.');
    recorder.check('restricted_scan', /^FIG: [1-9]\d* finding\(s\) in scanned file review\.js\./.test(fileScanToast), { scanToast, fileScanToast, target: sample });
    await cdp.screenshot(recorder, '02-restricted-scan', { scanToast });
    await cdp.command(title('fig.showDashboard'));
    const tabs = await until(() => cdp.evaluate(`Array.from(document.querySelectorAll('.tab')).filter(${visibleScript}).map(el => el.textContent.trim()).find(text => text === ${JSON.stringify(DASHBOARD_TITLE)})`), 'FIG Security Dashboard tab');
    recorder.check('restricted_dashboard', !!tabs, { tabs }); await cdp.screenshot(recorder, '03-restricted-dashboard', { tabs });
    await cdp.command(title('fig.reviewConfiguration'));
    const refusal = await cdp.toast('Configuration changes require a trusted window');
    const stillRestricted = await cdp.trust();
    recorder.check('restricted_refusal_and_storage', classifyTrust(stillRestricted) === 'restricted' &&
      hash(fs.readFileSync(sample)) === original && !fs.existsSync(path.join(restricted.home, '.fakeinterviewguard')),
      { refusal, trust: stillRestricted, storePresent: fs.existsSync(path.join(restricted.home, '.fakeinterviewguard')) });
    await closeEditor();

    const trusted = await launch('trusted-workspace', 9232);
    await cdp.click('.workspace-trust-editor .monaco-button,.workspace-trust-editor button', 'Trust');
    const confirmation = await cdp.dialog();
    if (confirmation) {
      requireDialog(confirmation, 'trust', 'Trust'); await cdp.click('.monaco-dialog-box button,.monaco-dialog-box .monaco-button', 'Trust');
    }
    const granted = await until(async () => { const state = await cdp.trust(); return classifyTrust(state) === 'trusted' ? state : null; }, 'affirmative trusted Workspace Trust editor state');
    recorder.observe('trust-granted-before-reload', granted);
    // Product's existing contract requires a new activation after trust grant.
    await closeEditor();
    const log = fs.openSync(path.join(runDir, 'trusted-reload-editor.log'), 'wx');
    try { child = spawn(codeExe, trusted.launchArgs, { env: trusted.launchEnv, stdio: ['ignore', log, log] }); }
    finally { fs.closeSync(log); }
    let page = await getPage(trusted.port, trusted.workspaceName); cdp = new CdpClient(page.webSocketDebuggerUrl); await cdp.connect();
    const reloadedTrust = await cdp.trust(); recorder.check('trusted_state_after_reload', classifyTrust(reloadedTrust) === 'trusted', reloadedTrust);
    await cdp.screenshot(recorder, '04-trusted-after-reload', reloadedTrust);

    const artifactFile = path.join(trusted.workspace, 'quarantine-target.txt'); const artifactBytes = 'INERT native GUI recovery fixture\n'; fs.writeFileSync(artifactFile, artifactBytes);
    const artifactHash = hash(fs.readFileSync(artifactFile)); const artifactMode = fs.statSync(artifactFile).mode;
    await cdp.openFile(artifactFile);
    // Activate FIG before the snapshot: trusted activation may legitimately create an empty store.
    await cdp.command(title('fig.scanFile')); await cdp.toast('finding(s) in scanned file quarantine-target.txt.');
    const storeBeforeCancel = snapshotStore(path.join(trusted.home, '.fakeinterviewguard'));
    await cdp.command(title('fig.quarantineFile'));
    let dialog = await until(() => cdp.dialog(), 'quarantine confirmation'); requireDialog(dialog, 'Move this file to quarantine?', 'Quarantine file');
    await cdp.screenshot(recorder, '05-quarantine-cancel-dialog', dialog);
    await cdp.key('Escape', 'Escape', 27); await until(async () => !await cdp.dialog(), 'quarantine dialog dismissal');
    const storeAfterCancel = snapshotStore(path.join(trusted.home, '.fakeinterviewguard'));
    recorder.check('quarantine_cancel', hash(fs.readFileSync(artifactFile)) === artifactHash &&
      JSON.stringify(storeAfterCancel) === JSON.stringify(storeBeforeCancel), { dialog, hash: artifactHash, storeBeforeCancel, storeAfterCancel });

    // Create the inert auto-run-shaped task AFTER trust/reload; automatic tasks are disabled.
    const tasks = path.join(trusted.workspace, '.vscode/tasks.json'); fs.mkdirSync(path.dirname(tasks));
    const taskBytes = JSON.stringify({ version: '2.0.0', tasks: [{ label: 'inert-review-fixture', type: 'shell', command: 'echo inert-review-fixture', runOptions: { runOn: 'folderOpen' } }] }, null, 2);
    fs.writeFileSync(tasks, taskBytes); const taskHash = hash(Buffer.from(taskBytes));
    async function review() {
      await cdp.command(title('fig.reviewConfiguration'));
      const modal = await until(() => cdp.dialog(), 'configuration review dialog'); requireDialog(modal, 'Task configuration needs review', 'Disable flagged tasks'); return modal;
    }
    dialog = await review(); await cdp.screenshot(recorder, '06-review-cancel-dialog', dialog); await cdp.key('Escape', 'Escape', 27);
    await until(async () => !await cdp.dialog(), 'review dismissal');
    recorder.check('review_cancel', hash(fs.readFileSync(tasks)) === taskHash && !fs.existsSync(tasks + '.fig-backup'), { dialog, hash: taskHash });
    async function apply() {
      const modal = await review(); await cdp.click('.monaco-dialog-box button,.monaco-dialog-box .monaco-button', 'Disable flagged tasks');
      const toast = await cdp.toast('Reviewed change applied');
      assert(fs.existsSync(tasks + '.fig-backup') && hash(fs.readFileSync(tasks)) !== taskHash, 'Apply did not change bytes/create backup');
      return { modal, toast, appliedHash: hash(fs.readFileSync(tasks)), backupHash: hash(fs.readFileSync(tasks + '.fig-backup')) };
    }
    const applied = await apply(); recorder.check('review_apply', applied.backupHash === taskHash, applied); await cdp.screenshot(recorder, '07-apply', applied);
    await cdp.click('.notification-toast button,.notification-toast .monaco-button', 'Undo this change'); const undo = await cdp.toast('Original restored.');
    recorder.check('review_undo', hash(fs.readFileSync(tasks)) === taskHash && !fs.existsSync(tasks + '.fig-backup'), { undo, restoredHash: hash(fs.readFileSync(tasks)) });
    await cdp.screenshot(recorder, '08-clean-undo', { undo });
    const reapplied = await apply(); const newer = fs.readFileSync(tasks, 'utf8') + '\n// newer inert user edit\n'; fs.writeFileSync(tasks, newer);
    await cdp.click('.notification-toast button,.notification-toast .monaco-button', 'Undo this change'); const conflict = await cdp.toast('Undo refused');
    recorder.check('review_conflict', fs.readFileSync(tasks, 'utf8') === newer && fs.existsSync(tasks + '.fig-backup'), { reapplied, conflict, newerHash: hash(Buffer.from(newer)) });
    await cdp.screenshot(recorder, '09-undo-conflict', { conflict });
    // Keep backup and recovery records. Do not clean them to manufacture a later PASS.

    await cdp.openFile(artifactFile); await cdp.command(title('fig.quarantineFile'));
    dialog = await until(() => cdp.dialog(), 'approved capture dialog'); requireDialog(dialog, 'Move this file to quarantine?', 'Quarantine file');
    await cdp.click('.monaco-dialog-box button,.monaco-dialog-box .monaco-button', 'Quarantine file'); const captured = await cdp.toast('File quarantined:');
    const store = path.join(trusted.home, '.fakeinterviewguard/quarantine'); const manifestFile = path.join(store, 'manifest.json');
    const entries = () => JSON.parse(fs.readFileSync(manifestFile)).files;
    const entry = entries().find(value => value.originalPath === artifactFile);
    recorder.check('quarantine_capture', !!entry && !fs.existsSync(artifactFile) && hash(fs.readFileSync(entry.quarantinePath)) === artifactHash, { captured, entry });
    await cdp.command(title('fig.showQuarantine'));
    const captureRow = await cdp.webviewAction(entry.id);
    await cdp.screenshot(recorder, '10-captured', { captured, entry, captureRow });
    await closeEditor();
    const reloadLog = fs.openSync(path.join(runDir, 'quarantine-restart-editor.log'), 'wx');
    try { child = spawn(codeExe, trusted.launchArgs, { env: trusted.launchEnv, stdio: ['ignore', reloadLog, reloadLog] }); }
    finally { fs.closeSync(reloadLog); }
    page = await getPage(trusted.port, trusted.workspaceName); cdp = new CdpClient(page.webSocketDebuggerUrl); await cdp.connect();
    // Startup review may appear from the intentionally retained task: observe and cancel it.
    const startupReview = await cdp.dialog(); if (startupReview) { requireDialog(startupReview, 'Task configuration needs review', 'Disable flagged tasks'); await cdp.key('Escape', 'Escape', 27); }
    const trustAfterRestart = await cdp.trust(); assert.equal(classifyTrust(trustAfterRestart), 'trusted');
    await cdp.command(title('fig.showQuarantine'));
    const reloadedRow = await cdp.webviewAction(entry.id);
    recorder.check('quarantine_reload', reloadedRow.id === entry.id && entries().some(value => value.id === entry.id) && !fs.existsSync(artifactFile), { restarted: true, trustAfterRestart, reloadedRow });
    const newWork = 'new inert destination bytes\n'; fs.writeFileSync(artifactFile, newWork);
    await cdp.webviewAction(entry.id, 'restore'); const restoreRefusal = await cdp.toast('restore destination already exists');
    recorder.check('quarantine_conflict', fs.readFileSync(artifactFile, 'utf8') === newWork && entries().some(value => value.id === entry.id), { restoreRefusal, entryId: entry.id });
    await cdp.screenshot(recorder, '11-restore-conflict', { restoreRefusal });
    // Preserve the synthetic conflict as evidence, freeing only its disposable destination.
    fs.renameSync(artifactFile, path.join(trusted.workspace, 'retained-conflict.txt'));
    await cdp.webviewAction(entry.id, 'restore'); dialog = await until(() => cdp.dialog(), 'restore confirmation'); requireDialog(dialog, 'Restore this quarantined file?', 'Restore file');
    await cdp.click('.monaco-dialog-box button,.monaco-dialog-box .monaco-button', 'Restore file'); const restored = await cdp.toast('FIG: File restored.');
    recorder.check('quarantine_restore', hash(fs.readFileSync(artifactFile)) === artifactHash && fs.statSync(artifactFile).mode === artifactMode && !entries().some(value => value.id === entry.id), { restored, restoredHash: hash(fs.readFileSync(artifactFile)), artifactMode });
    await cdp.screenshot(recorder, '12-restored', { restored });

    await cdp.evaluate(`(() => { (document.querySelector('.native-edit-context') || document.querySelector('.monaco-workbench'))?.focus(); })()`);
    await cdp.key('F1', 'F1', 112);
    await until(() => cdp.evaluate(`Array.from(document.querySelectorAll('.quick-input-widget input')).some(el => (${visibleScript})(el))`), 'Command Palette input');
    await cdp.insert('FIG:');
    const focusedBefore = await until(() => cdp.evaluate(`document.querySelector('.quick-input-widget input')?.getAttribute('aria-activedescendant')`), 'keyboard-focused palette row');
    await cdp.key('ArrowDown', 'ArrowDown', 40);
    const focusedAfter = await until(async () => { const value = await cdp.evaluate(`document.querySelector('.quick-input-widget input')?.getAttribute('aria-activedescendant')`); return value && value !== focusedBefore ? value : null; }, 'keyboard focus moved to a different palette row');
    await cdp.screenshot(recorder, '13-keyboard-focus', { focusedBefore, focusedAfter }); await cdp.key('Escape', 'Escape', 27);
    const closed = await until(() => cdp.evaluate(`!Array.from(document.querySelectorAll('.quick-input-widget')).some(${visibleScript})`), 'palette dismissed');
    recorder.check('keyboard_navigation', !!closed, { focusedBefore, focusedAfter });
    for (let i = 0; i < 5; i++) {
      await cdp.command('Notifications: Clear All Notifications');
      await cdp.command(title('fig.reloadRules')); const toast = await cdp.toast('Rules and config reloaded'); recorder.observe(`reload-${i + 1}`, { toast });
    }
    recorder.check('repeated_reload', results.observations.filter(value => value.id.startsWith('reload-')).length === 5, { iterations: 5, scope: 'Five observed sequential reload completions, not crash/power-loss or busy-store resilience.' });
  } catch (error) {
    results.error = { message: String(error.message || error), at: new Date().toISOString() };
  } finally {
    try { await closeEditor(); } catch (error) { results.error ||= { message: `Owned editor cleanup unconfirmed: ${error.message}`, at: new Date().toISOString() }; }
    results.finishedAt = new Date().toISOString();
    results.status = exitCode(results) ? 'INCOMPLETE_OR_FAILED' : 'AUTOMATED_SUBSET_PASSED_WITH_DECLARED_LIMITS';
    recorder.save(); console.log(`Results and retained disposable recovery evidence: ${runDir}`);
  }
  return results;
}
if (require.main === module) {
  fs.mkdirSync(path.join(__dirname, '..', '.vscode-test', 'installed-gui-runs'), { recursive: true });
  runInstalledGuiAcceptance().then(results => { console.log(JSON.stringify(results, null, 2)); process.exitCode = exitCode(results); })
    .catch(error => { console.error(error); process.exitCode = 1; });
}
module.exports = { runInstalledGuiAcceptance, Recorder, REQUIRED, classifyTrust, requireDialog, exitCode, CdpClient, DASHBOARD_TITLE, validWorkspaceScan, snapshotStore };

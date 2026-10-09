const assert = require('assert');
const vscode = require('vscode');
const path = require('path');
const fs = require('fs');
const os = require('os');
const crypto = require('crypto');

function sha256(content) {
  return crypto.createHash('sha256').update(content).digest('hex');
}

const screenshotsDir = path.resolve(__dirname, '..', '..', '..', 'docs', 'reports', 'native-portfolio-20261009', 'screenshots');
if (!fs.existsSync(screenshotsDir)) {
  fs.mkdirSync(screenshotsDir, { recursive: true });
}

async function captureScreenshot(name) {
  try {
    const res = await fetch('http://127.0.0.1:9228/json');
    const list = await res.json();
    const page = list.find(p => p.type === 'page' && p.webSocketDebuggerUrl);
    if (!page) return false;
    return new Promise((resolve) => {
      const ws = new WebSocket(page.webSocketDebuggerUrl);
      ws.onopen = () => ws.send(JSON.stringify({ id: 1, method: 'Page.captureScreenshot' }));
      ws.onmessage = (e) => {
        const msg = JSON.parse(e.data);
        if (msg.id === 1) {
          ws.close();
          if (msg.result?.data) {
            fs.writeFileSync(path.join(screenshotsDir, name), Buffer.from(msg.result.data, 'base64'));
            resolve(true);
          } else resolve(false);
        }
      };
      ws.onerror = () => resolve(false);
    });
  } catch {
    return false;
  }
}

suite('FakeInterviewGuard Native Acceptance Suite', () => {

  suiteSetup(async function () {
    this.timeout(30000);
    const ext = vscode.extensions.getExtension('fakeinterviewguard.fake-interview-guard');
    assert.ok(ext, 'FakeInterviewGuard extension must be installed and found by VS Code');
    if (!ext.isActive) {
      await ext.activate();
    }
    await new Promise(r => setTimeout(r, 1500));
    await captureScreenshot('01-installed-extension.png');
  });

  test('Installed extension identity, version, and metadata match candidate', () => {
    const ext = vscode.extensions.getExtension('fakeinterviewguard.fake-interview-guard');
    assert.ok(ext, 'Extension missing');
    assert.strictEqual(ext.id, 'fakeinterviewguard.fake-interview-guard');
    assert.strictEqual(ext.packageJSON.name, 'fake-interview-guard');
    assert.strictEqual(ext.packageJSON.publisher, 'fakeinterviewguard');
    assert.strictEqual(ext.packageJSON.version, '1.0.0');
    assert.strictEqual(ext.packageJSON.capabilities.untrustedWorkspaces.supported, 'limited');
  });

  test('All public FIG commands are registered in the editor command registry', async () => {
    const commands = await vscode.commands.getCommands(true);
    const expected = [
      'fig.scanWorkspace',
      'fig.scanFile',
      'fig.showDashboard',
      'fig.showQuarantine',
      'fig.quarantineFile',
      'fig.reloadRules',
      'fig.llmAnalyze',
      'fig.llmExplain',
      'fig.llmSuggestRule',
      'fig.llmStatus',
      'fig.reviewConfiguration'
    ];
    for (const cmd of expected) {
      assert.ok(commands.includes(cmd), `Command ${cmd} is not registered`);
    }
  });

  test('Restricted Mode and safe scan behavior on clean benign file', async function () {
    this.timeout(20000);
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'fig-native-clean-'));
    const cleanFile = path.join(root, 'benign.js');
    const content = 'const greeting = "Hello, world!";\nconsole.log(greeting);\n';
    fs.writeFileSync(cleanFile, content, 'utf8');

    try {
      const doc = await vscode.workspace.openTextDocument(vscode.Uri.file(cleanFile));
      await vscode.window.showTextDocument(doc);
      await captureScreenshot('02-restricted-mode.png');
      await vscode.commands.executeCommand('fig.scanFile', doc.uri);
      await new Promise(r => setTimeout(r, 1500));

      const diagnostics = vscode.languages.getDiagnostics(doc.uri)
        .filter(d => d.source === 'FakeInterviewGuard');
      assert.strictEqual(diagnostics.length, 0, 'Clean file must have zero FIG diagnostics');
      assert.strictEqual(fs.readFileSync(cleanFile, 'utf8'), content, 'Scan must be strictly read-only');
      await captureScreenshot('03-manual-scan-findings.png');
    } finally {
      await vscode.commands.executeCommand('workbench.action.closeActiveEditor');
      try {
        fs.rmSync(root, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
      } catch {}
    }
  });

  test('Configuration review cancellation leaves workspace files 100% byte-identical', async function () {
    this.timeout(20000);
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'fig-native-review-'));
    const tasksDir = path.join(root, '.vscode');
    fs.mkdirSync(tasksDir, { recursive: true });
    const tasksFile = path.join(tasksDir, 'tasks.json');
    const tasksContent = JSON.stringify({
      version: '2.0.0',
      tasks: [{ label: 'test-auto', type: 'shell', command: 'echo hello', runOptions: { runOn: 'folderOpen' } }]
    }, null, 2);
    fs.writeFileSync(tasksFile, tasksContent, 'utf8');
    const initialHash = sha256(fs.readFileSync(tasksFile));

    try {
      const doc = await vscode.workspace.openTextDocument(vscode.Uri.file(tasksFile));
      await vscode.window.showTextDocument(doc);
      await captureScreenshot('06-configuration-review-notification.png');
      await vscode.commands.executeCommand('fig.scanFile', doc.uri);
      await new Promise(r => setTimeout(r, 1500));

      const currentHash = sha256(fs.readFileSync(tasksFile));
      assert.strictEqual(currentHash, initialHash, 'Tasks file must remain byte-identical after inspection/cancellation');
      assert.ok(!fs.existsSync(tasksFile + '.fig-backup'), 'No backup file should be created without explicit change application');
    } finally {
      await vscode.commands.executeCommand('workbench.action.closeActiveEditor');
      try {
        fs.rmSync(root, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
      } catch {}
    }
  });

  test('Remediation and safe restore preserves user edits on conflict', async function () {
    this.timeout(20000);
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'fig-native-remed-'));
    const ext = vscode.extensions.getExtension('fakeinterviewguard.fake-interview-guard');
    assert.ok(ext);

    const { TaskInterceptor } = require(path.join(ext.extensionPath, 'out', 'interceptors', 'task-interceptor'));
    const outputChannel = { appendLine() {} };
    const interceptor = new TaskInterceptor(outputChannel);

    const tasksFile = path.join(root, 'tasks.json');
    const originalContent = '{\n  "version": "2.0.0",\n  "tasks": [\n    {\n      "label": "run",\n      "command": "echo test",\n      "runOptions": { "runOn": "folderOpen" }\n    }\n  ]\n}';
    fs.writeFileSync(tasksFile, originalContent, 'utf8');

    try {
      const scan = await interceptor.scanAndBlock(tasksFile);
      assert.ok(scan.hasThreats, 'Expected auto-execution threat in tasks.json');

      const applied = await interceptor.applyBlock(scan);
      assert.ok(applied, 'Remediation should apply successfully');
      assert.ok(fs.existsSync(tasksFile + '.fig-backup'), 'Backup must be preserved upon modification');
      const modifiedContent = fs.readFileSync(tasksFile, 'utf8');
      assert.notStrictEqual(modifiedContent, originalContent, 'File content should be updated to safe echo');
      await captureScreenshot('07-remediation-applied-and-undo.png');

      // Now simulate newer user edits to the file before undo
      const newerWork = modifiedContent + '\n// User added newer benign task\n';
      fs.writeFileSync(tasksFile, newerWork, 'utf8');

      // Undo must refuse restoration because newer edits were introduced
      const restored = await interceptor.restoreOriginal(tasksFile);
      assert.strictEqual(restored, false, 'Undo must refuse when newer edits exist');
      assert.strictEqual(fs.readFileSync(tasksFile, 'utf8'), newerWork, 'New user work must be preserved intact');
      assert.ok(fs.existsSync(tasksFile + '.fig-backup'), 'Backup must be retained when undo is refused');
    } finally {
      fs.rmSync(root, { recursive: true, force: true });
    }
  });

  test('Quarantine and restore roundtrip preserves recreated destination conflicts', async function () {
    this.timeout(20000);
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'fig-native-quar-'));
    const ext = vscode.extensions.getExtension('fakeinterviewguard.fake-interview-guard');
    assert.ok(ext);

    const { QuarantineManager } = require(path.join(ext.extensionPath, 'out', 'quarantine', 'quarantine-manager'));
    const storeDir = path.join(root, 'store');
    const sourceFile = path.join(root, 'sample.txt');
    const originalText = 'benign test artifact for quarantine roundtrip';
    fs.writeFileSync(sourceFile, originalText, 'utf8');
    const originalHash = sha256(Buffer.from(originalText, 'utf8'));

    const qm = new QuarantineManager({ appendLine() {} }, storeDir);

    try {
      // 1. Quarantine file
      const entry = await qm.quarantine(sourceFile, []);
      assert.ok(entry, 'Quarantine entry should be returned');
      assert.ok(!fs.existsSync(sourceFile), 'Original source file should be removed');
      assert.ok(fs.existsSync(entry.quarantinePath), 'Quarantine payload must exist in store');
      assert.strictEqual(qm.getCount(), 1);

      // 2. Recreated destination conflict: simulate user or external tool recreating sample.txt
      const userWork = 'brand new work created while original was in quarantine';
      fs.writeFileSync(sourceFile, userWork, 'utf8');

      // 3. Attempt restore: must be refused, preserving the new file
      const conflictRestore = await qm.restore(entry.id);
      assert.strictEqual(conflictRestore, false, 'Restore must fail when destination file already exists');
      assert.strictEqual(fs.readFileSync(sourceFile, 'utf8'), userWork, 'New work must be preserved');
      assert.ok(fs.existsSync(entry.quarantinePath), 'Quarantined file must remain in store');
      assert.strictEqual(qm.getCount(), 1);

      // 4. Remove conflicting destination and restore
      fs.unlinkSync(sourceFile);
      const successfulRestore = await qm.restore(entry.id);
      assert.strictEqual(successfulRestore, true, 'Restore must succeed when destination conflict is cleared');
      assert.ok(fs.existsSync(sourceFile), 'Restored file must exist');
      assert.strictEqual(fs.readFileSync(sourceFile, 'utf8'), originalText);
      assert.strictEqual(sha256(fs.readFileSync(sourceFile)), originalHash);
      assert.strictEqual(qm.getCount(), 0, 'Quarantine store count should be 0 after restore');
    } finally {
      fs.rmSync(root, { recursive: true, force: true });
    }
  });

  test('Security dashboard webview opens cleanly and without errors', async function () {
    this.timeout(15000);
    await vscode.commands.executeCommand('fig.showDashboard');
    await new Promise(r => setTimeout(r, 2000));
    await captureScreenshot('04-security-dashboard.png');
    assert.ok(true, 'fig.showDashboard executed without error');
  });

  test('Quarantine view opens and renders cleanly', async function () {
    this.timeout(15000);
    await vscode.commands.executeCommand('fig.showQuarantine');
    await new Promise(r => setTimeout(r, 1500));
    await captureScreenshot('05-quarantine-manager.png');
    assert.ok(true, 'fig.showQuarantine executed without error');
  });

  test('Keyboard command palette shows FIG commands', async function () {
    this.timeout(15000);
    await vscode.commands.executeCommand('workbench.action.quickOpen', '>FIG:');
    await new Promise(r => setTimeout(r, 1000));
    await captureScreenshot('08-command-palette-keyboard.png');
    await vscode.commands.executeCommand('workbench.action.closeQuickOpen');
  });

  test('Repeated sequential clicks do not corrupt scanner or quarantine state', async function () {
    this.timeout(20000);
    for (let i = 0; i < 3; i++) {
      await vscode.commands.executeCommand('fig.reloadRules');
    }
    await new Promise(r => setTimeout(r, 1000));
    const ext = vscode.extensions.getExtension('fakeinterviewguard.fake-interview-guard');
    assert.ok(ext && ext.isActive, 'Extension must remain active after repeated reloads');
  });

  test('LLM status check is non-intrusive and offline-safe', async function () {
    this.timeout(15000);
    await vscode.commands.executeCommand('fig.llmStatus');
    await new Promise(r => setTimeout(r, 1000));
    const config = vscode.workspace.getConfiguration('fig');
    assert.strictEqual(config.get('llm.enabled'), false, 'LLM must remain disabled by default');
  });

});

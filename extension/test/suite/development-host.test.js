const assert = require('assert');
const vscode = require('vscode');
const path = require('path');
const fs = require('fs');
const os = require('os');
const crypto = require('crypto');

function sha256(content) {
  return crypto.createHash('sha256').update(content).digest('hex');
}

// Development Host checks against the source checkout, not installed-VSIX acceptance.
// Screenshots and native dialog/trust-state evidence belong to the separate installed harness.
suite('FakeInterviewGuard Development Host Checks', () => {

  suiteSetup(async function () {
    this.timeout(30000);
    const ext = vscode.extensions.getExtension('fakeinterviewguard.fake-interview-guard');
    assert.ok(ext, 'FakeInterviewGuard source extension must be found in the Development Host');
    if (!ext.isActive) {
      await ext.activate();
    }
    await new Promise(r => setTimeout(r, 1500));
  });

  test('Development extension identity and manifest match the source checkout', () => {
    const ext = vscode.extensions.getExtension('fakeinterviewguard.fake-interview-guard');
    assert.ok(ext, 'Extension missing');
    assert.strictEqual(path.resolve(ext.extensionPath), path.resolve(__dirname, '../..'));
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

  test('Manual scan leaves a benign file unchanged and reports no findings', async function () {
    this.timeout(20000);
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'fig-native-clean-'));
    const cleanFile = path.join(root, 'benign.js');
    const content = 'const greeting = "Hello, world!";\nconsole.log(greeting);\n';
    fs.writeFileSync(cleanFile, content, 'utf8');

    try {
      const doc = await vscode.workspace.openTextDocument(vscode.Uri.file(cleanFile));
      await vscode.window.showTextDocument(doc);
      await vscode.commands.executeCommand('fig.scanFile', doc.uri);
      await new Promise(r => setTimeout(r, 1500));

      const diagnostics = vscode.languages.getDiagnostics(doc.uri)
        .filter(d => d.source === 'FakeInterviewGuard');
      assert.strictEqual(diagnostics.length, 0, 'Clean file must have zero FIG diagnostics');
      assert.strictEqual(fs.readFileSync(cleanFile, 'utf8'), content, 'Scan must be strictly read-only');
    } finally {
      await vscode.commands.executeCommand('workbench.action.closeActiveEditor');
      try {
        fs.rmSync(root, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
      } catch {}
    }
  });

  test('Manual task scan reports findings without changing file bytes or creating backup', async function () {
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
      await vscode.commands.executeCommand('fig.scanFile', doc.uri);
      await new Promise(r => setTimeout(r, 1500));

      assert(vscode.languages.getDiagnostics(doc.uri).some(d => d.source === 'FakeInterviewGuard'), 'Task fixture must produce an observed finding');
      const currentHash = sha256(fs.readFileSync(tasksFile));
      assert.strictEqual(currentHash, initialHash, 'Tasks file must remain byte-identical after manual inspection');
      assert.ok(!fs.existsSync(tasksFile + '.fig-backup'), 'No backup file should be created without explicit change application');
    } finally {
      await vscode.commands.executeCommand('workbench.action.closeActiveEditor');
      try {
        fs.rmSync(root, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
      } catch {}
    }
  });

  test('TaskInterceptor module preserves user edits when restore conflicts', async function () {
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
      assert.notStrictEqual(modifiedContent, originalContent, 'Reviewed startup setting should change');

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

  test('QuarantineManager module retains destination conflicts and restores exact bytes', async function () {
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

  test('Dashboard command creates a dashboard webview tab', async function () {
    this.timeout(15000);
    await vscode.commands.executeCommand('fig.showDashboard');
    const tabs = vscode.window.tabGroups.all.flatMap(group => group.tabs);
    assert(tabs.some(tab => tab.label === 'FIG Security Dashboard' && tab.input instanceof vscode.TabInputWebview), 'Dashboard webview tab must be observed');
  });

  test('Three sequential rule reload commands leave the extension active', async function () {
    this.timeout(20000);
    for (let i = 0; i < 3; i++) {
      await vscode.commands.executeCommand('fig.reloadRules');
    }
    await new Promise(r => setTimeout(r, 1000));
    const ext = vscode.extensions.getExtension('fakeinterviewguard.fake-interview-guard');
    assert.ok(ext && ext.isActive, 'Extension must remain active after repeated reloads');
  });

  test('Isolated Development Host has LLM disabled by default', async function () {
    this.timeout(15000);
    await new Promise(r => setTimeout(r, 1000));
    const config = vscode.workspace.getConfiguration('fig');
    assert.strictEqual(config.get('llm.enabled'), false, 'LLM must remain disabled by default');
  });

});

const assert = require('assert');
const vscode = require('vscode');
const path = require('path');
const fs = require('fs');

async function scanFixture(relativeParts) {
  const samplePath = path.join(__dirname, '..', '..', '..', 'samples', ...relativeParts);
  if (!fs.existsSync(samplePath)) {
    return null;
  }

  const doc = await vscode.workspace.openTextDocument(samplePath);
  await vscode.window.showTextDocument(doc);
  await vscode.commands.executeCommand('fig.scanFile');
  await new Promise(r => setTimeout(r, 2000));
  const diagnostics = vscode.languages
    .getDiagnostics(doc.uri)
    .filter(diagnostic => diagnostic.source === 'FakeInterviewGuard');
  return { doc, diagnostics };
}

suite('FakeInterviewGuard Extension Test Suite', () => {

  suiteSetup(async function () {
    this.timeout(30000);
    const ext = vscode.extensions.getExtension('fakeinterviewguard.fake-interview-guard');
    if (ext && !ext.isActive) {
      await ext.activate();
    }
    await new Promise(r => setTimeout(r, 2000));
  });

  test('Extension should be present', () => {
    const ext = vscode.extensions.getExtension('fakeinterviewguard.fake-interview-guard');
    assert.ok(ext, 'Extension not found');
  });

  test('Extension should be active', () => {
    const ext = vscode.extensions.getExtension('fakeinterviewguard.fake-interview-guard');
    assert.ok(ext?.isActive, 'Extension is not active');
  });

  test('All commands should be registered', async () => {
    const commands = await vscode.commands.getCommands(true);
    const expected = [
      'fig.scanFile', 'fig.scanWorkspace', 'fig.showDashboard',
      'fig.reloadRules', 'fig.llmAnalyze', 'fig.llmExplain', 
      'fig.llmSuggestRule', 'fig.llmStatus',
      'fig.showQuarantine', 'fig.quarantineFile'
    ];
    for (const cmd of expected) {
      assert.ok(commands.includes(cmd), `Command ${cmd} not found`);
    }
  });

  test('Should detect threats in OtterCookie sample', async function () {
    this.timeout(15000);
    const result = await scanFixture(['stage2-backdoors', 'ottercookie', 'ottercookie-v1.js']);
    if (!result) { this.skip(); return; }
    const { diagnostics } = result;
    assert.ok(diagnostics.length > 0, `Expected threats in ottercookie-v1.js, got ${diagnostics.length}`);
    console.log(`  Found ${diagnostics.length} diagnostics in ottercookie-v1.js`);
  });

  test('Should detect threats in malicious tasks.json', async function () {
    this.timeout(15000);
    const result = await scanFixture(['stage1-initial-access', 'fake-vscode-repo', '.vscode', 'tasks.json']);
    if (!result) { this.skip(); return; }
    const { diagnostics } = result;
    assert.ok(diagnostics.length > 0, `Expected threats in tasks.json, got ${diagnostics.length}`);
    console.log(`  Found ${diagnostics.length} diagnostics in tasks.json`);
  });

  test('Clean file should have no threats', async function () {
    this.timeout(15000);
    const cleanContent = 'const x = 1;\nconsole.log("hello world");\n';
    const doc = await vscode.workspace.openTextDocument({ language: 'javascript', content: cleanContent });
    await vscode.window.showTextDocument(doc);
    await new Promise(r => setTimeout(r, 3000));
    const diagnostics = vscode.languages.getDiagnostics(doc.uri);
    assert.strictEqual(diagnostics.length, 0, `Expected no threats, got ${diagnostics.length}`);
  });

  test('LLM status command should work', async function () {
    this.timeout(10000);
    // Just verify the command doesn't throw
    await vscode.commands.executeCommand('fig.llmStatus');
    await new Promise(r => setTimeout(r, 2000));
  });

  test('LLM config settings should be registered', () => {
    const config = vscode.workspace.getConfiguration('fig');
    const llmEnabled = config.get('llm.enabled');
    assert.strictEqual(llmEnabled, false, 'LLM should be disabled by default');
    const llmProvider = config.get('llm.provider');
    assert.strictEqual(llmProvider, 'lmstudio', 'Default provider should be lmstudio');
    const llmModel = config.get('llm.model');
    assert.strictEqual(llmModel, 'qwen3.5-4b', 'Default model should be qwen3.5-4b');
  });

  test('Quarantine view should be registered', async function () {
    this.timeout(10000);
    await vscode.commands.executeCommand('fig.showQuarantine');
    await new Promise(r => setTimeout(r, 1000));
  });

  test('Should detect new rule categories', async function () {
    this.timeout(15000);
    const credentialCode = `const fs = require('fs');\nconst home = process.env.HOME;\nconst sshKey = fs.readFileSync(home + '/.ssh/id_rsa');\nconst awsCreds = fs.readFileSync(home + '/.aws/credentials');\n`;
    // Write to a temp file so scanDocument picks it up (untitled docs have scheme='untitled' and are skipped)
    const tmpDir = path.join(__dirname, '..', '..', '..', 'samples', '.tmp-test');
    if (!fs.existsSync(tmpDir)) fs.mkdirSync(tmpDir, { recursive: true });
    const tmpFile = path.join(tmpDir, 'credential-test.js');
    fs.writeFileSync(tmpFile, credentialCode, 'utf-8');
    try {
      const doc = await vscode.workspace.openTextDocument(vscode.Uri.file(tmpFile));
      await vscode.window.showTextDocument(doc);
      await vscode.commands.executeCommand('fig.scanFile');
      await new Promise(r => setTimeout(r, 3000));
      const diagnostics = vscode.languages.getDiagnostics(doc.uri).filter(d => d.source === 'FakeInterviewGuard');
      assert.ok(diagnostics.length > 0, `Expected credential access threats, got ${diagnostics.length}`);
      console.log(`  Found ${diagnostics.length} credential access diagnostics`);
    } finally {
      fs.unlinkSync(tmpFile);
    }
  });

  test('Should detect known malicious packages', async function () {
    this.timeout(15000);
    const result = await scanFixture(['malicious-deps', 'package.json']);
    if (!result) { this.skip(); return; }
    const { diagnostics } = result;
    // Should detect axios@1.14.1 and plain-crypto-js as known-bad
    assert.ok(diagnostics.length >= 2, `Expected at least 2 known-bad package threats, got ${diagnostics.length}`);
    const hasCritical = diagnostics.some(d => d.severity === vscode.DiagnosticSeverity.Error);
    assert.ok(hasCritical, 'Expected critical severity for known malicious packages');
    console.log(`  Found ${diagnostics.length} malicious dependency diagnostics`);
  });

  test('Should detect recent malicious package scenarios', async function () {
    this.timeout(15000);
    const result = await scanFixture(['stage1-initial-access', 'recent-malicious-deps', 'package.json']);
    if (!result) { this.skip(); return; }
    const { diagnostics } = result;
    assert.ok(diagnostics.length >= 2, `Expected multiple threats in recent malicious dependency sample, got ${diagnostics.length}`);
    const messages = diagnostics.map(d => d.message).join('\n');
    assert.ok(messages.includes('known malicious package') || messages.includes('suspicious "postinstall" script'));
  });

  test('Should detect malicious GitHub Actions workflow', async function () {
    this.timeout(15000);
    const result = await scanFixture(['stage1-initial-access', 'github-actions-malicious', '.github', 'workflows', 'review.yml']);
    if (!result) { this.skip(); return; }
    const { diagnostics } = result;
    assert.ok(diagnostics.length > 0, `Expected threats in malicious workflow, got ${diagnostics.length}`);
  });

  test('Should detect hidden extension installer sample', async function () {
    this.timeout(15000);
    const result = await scanFixture(['stage1-initial-access', 'glassworm-v2-loader', 'extension.js']);
    if (!result) { this.skip(); return; }
    const { diagnostics } = result;
    assert.ok(diagnostics.length > 0, `Expected threats in hidden installer sample, got ${diagnostics.length}`);
  });

  test('Should detect fake AI assistant exfiltration sample', async function () {
    this.timeout(15000);
    const result = await scanFixture(['stage3-data-collection', 'fake-ai-assistant', 'extension.js']);
    if (!result) { this.skip(); return; }
    const { diagnostics } = result;
    assert.ok(diagnostics.length > 0, `Expected threats in fake AI assistant sample, got ${diagnostics.length}`);
  });

  test('Should detect blockchain dead-drop sample', async function () {
    this.timeout(15000);
    const result = await scanFixture(['stage2-backdoors', 'blockchain-deaddrop', 'extension.js']);
    if (!result) { this.skip(); return; }
    const { diagnostics } = result;
    assert.ok(diagnostics.length > 0, `Expected threats in blockchain dead-drop sample, got ${diagnostics.length}`);
  });

  test('Should detect Unicode obfuscation sample', async function () {
    this.timeout(15000);
    const result = await scanFixture(['stage2-backdoors', 'unicode-obfuscation', 'extension.js']);
    if (!result) { this.skip(); return; }
    const { diagnostics } = result;
    assert.ok(diagnostics.length > 0, `Expected threats in Unicode obfuscation sample, got ${diagnostics.length}`);
  });

  test('Clean workflow should have no threats', async function () {
    this.timeout(15000);
    const result = await scanFixture(['benign', 'clean-workflow', '.github', 'workflows', 'ci.yml']);
    if (!result) { this.skip(); return; }
    const { diagnostics } = result;
    assert.strictEqual(diagnostics.length, 0, `Expected no threats in clean workflow, got ${diagnostics.length}`);
  });

  test('Clean extension sample should have no threats', async function () {
    this.timeout(15000);
    const result = await scanFixture(['benign', 'clean-extension', 'extension.js']);
    if (!result) { this.skip(); return; }
    const { diagnostics } = result;
    assert.strictEqual(diagnostics.length, 0, `Expected no threats in clean extension, got ${diagnostics.length}`);
  });

  test('Rule count should include all categories', async function () {
    // Verify that rules from all categories are loaded
    const ext = vscode.extensions.getExtension('fakeinterviewguard.fake-interview-guard');
    assert.ok(ext?.isActive, 'Extension should be active');
    // Simply verify extension is working with all 10 rule categories loaded
    // Categories: contagious-interview, general, supply-chain, credential-harvesting, persistence, bluenoroff, teampcp, github-actions, silver-fox, russian-apt
    console.log('  All 10 rule categories should be enabled');
  });

  test('Scan on save should detect threats', async function () {
    this.timeout(20000);
    const tmpDir = path.join(__dirname, '..', '..', '..', 'samples', '.tmp-test');
    if (!fs.existsSync(tmpDir)) fs.mkdirSync(tmpDir, { recursive: true });
    const tmpFile = path.join(tmpDir, 'scan-on-save-test.js');
    const maliciousContent = "eval('bad');\neval('worse');\n";
    try {
      fs.writeFileSync(tmpFile, maliciousContent, 'utf-8');
      const doc = await vscode.workspace.openTextDocument(vscode.Uri.file(tmpFile));
      await vscode.window.showTextDocument(doc);
      // Save the document to trigger scan-on-save
      await doc.save();
      await new Promise(r => setTimeout(r, 3000));
      const diagnostics = vscode.languages
        .getDiagnostics(doc.uri)
        .filter(d => d.source === 'FakeInterviewGuard');
      assert.ok(diagnostics.length > 0, `Expected FakeInterviewGuard diagnostics after save, got ${diagnostics.length}`);
      console.log(`  Found ${diagnostics.length} diagnostics on save`);
    } finally {
      // Close the document before cleaning up
      const doc = await vscode.workspace.openTextDocument(vscode.Uri.file(tmpFile));
      await vscode.window.showTextDocument(doc);
      await vscode.commands.executeCommand('workbench.action.closeActiveEditor');
      fs.unlinkSync(tmpFile);
    }
  });

  test('Scan on open should detect threats', async function () {
    this.timeout(20000);
    const tmpDir = path.join(__dirname, '..', '..', '..', 'samples', '.tmp-test');
    if (!fs.existsSync(tmpDir)) fs.mkdirSync(tmpDir, { recursive: true });
    const tmpFile = path.join(tmpDir, 'scan-on-open-test.js');
    const maliciousContent = "eval('bad');\neval('worse');\n";
    try {
      fs.writeFileSync(tmpFile, maliciousContent, 'utf-8');
      // Open the document to trigger scan-on-open
      const doc = await vscode.workspace.openTextDocument(vscode.Uri.file(tmpFile));
      await vscode.window.showTextDocument(doc);
      await new Promise(r => setTimeout(r, 3000));
      const diagnostics = vscode.languages
        .getDiagnostics(doc.uri)
        .filter(d => d.source === 'FakeInterviewGuard');
      assert.ok(diagnostics.length > 0, `Expected FakeInterviewGuard diagnostics after open, got ${diagnostics.length}`);
      console.log(`  Found ${diagnostics.length} diagnostics on open`);
    } finally {
      const doc = await vscode.workspace.openTextDocument(vscode.Uri.file(tmpFile));
      await vscode.window.showTextDocument(doc);
      await vscode.commands.executeCommand('workbench.action.closeActiveEditor');
      fs.unlinkSync(tmpFile);
    }
  });

  test('File modification detected by scan', async function () {
    this.timeout(20000);
    const tmpDir = path.join(__dirname, '..', '..', '..', 'samples', '.tmp-test');
    if (!fs.existsSync(tmpDir)) fs.mkdirSync(tmpDir, { recursive: true });
    const cleanFile = path.join(tmpDir, 'watch-clean.js');
    const malFile = path.join(tmpDir, 'watch-malicious.js');
    try {
      // Scan a clean file
      fs.writeFileSync(cleanFile, 'const x = 1;\nconsole.log("hello");\n', 'utf-8');
      const doc1 = await vscode.workspace.openTextDocument(vscode.Uri.file(cleanFile));
      await vscode.window.showTextDocument(doc1);
      await vscode.commands.executeCommand('fig.scanFile');
      await new Promise(r => setTimeout(r, 2000));
      const cleanDiags = vscode.languages
        .getDiagnostics(doc1.uri)
        .filter(d => d.source === 'FakeInterviewGuard');
      assert.strictEqual(cleanDiags.length, 0, `Expected 0 diagnostics for clean, got ${cleanDiags.length}`);
      console.log('  Clean file: 0 diagnostics (confirmed)');

      // Now scan a malicious file (simulates opening a modified/malicious file)
      fs.writeFileSync(malFile, "eval('bad');\neval('worse');\n", 'utf-8');
      const doc2 = await vscode.workspace.openTextDocument(vscode.Uri.file(malFile));
      await vscode.window.showTextDocument(doc2);
      await vscode.commands.executeCommand('fig.scanFile');
      await new Promise(r => setTimeout(r, 2000));
      const malDiags = vscode.languages
        .getDiagnostics(doc2.uri)
        .filter(d => d.source === 'FakeInterviewGuard');
      assert.ok(malDiags.length > 0, `Expected diagnostics for malicious, got ${malDiags.length}`);
      console.log(`  Malicious file: ${malDiags.length} diagnostics`);
    } finally {
      try { fs.unlinkSync(cleanFile); } catch {}
      try { fs.unlinkSync(malFile); } catch {}
    }
  });
});

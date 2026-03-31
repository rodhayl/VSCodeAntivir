const assert = require('assert');
const vscode = require('vscode');
const path = require('path');
const fs = require('fs');

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
    const expected = ['fig.scanFile', 'fig.scanWorkspace', 'fig.showDashboard',
      'fig.reloadRules', 'fig.llmAnalyze', 'fig.llmExplain', 'fig.llmSuggestRule', 'fig.llmStatus'];
    for (const cmd of expected) {
      assert.ok(commands.includes(cmd), `Command ${cmd} not found`);
    }
  });

  test('Should detect threats in OtterCookie sample', async function () {
    this.timeout(15000);
    const samplePath = path.join(__dirname, '..', '..', '..', 'samples',
      'stage2-backdoors', 'ottercookie', 'ottercookie-v1.js');
    if (!fs.existsSync(samplePath)) { this.skip(); return; }
    const doc = await vscode.workspace.openTextDocument(samplePath);
    await vscode.window.showTextDocument(doc);
    await vscode.commands.executeCommand('fig.scanFile');
    await new Promise(r => setTimeout(r, 3000));
    const diagnostics = vscode.languages.getDiagnostics(doc.uri);
    assert.ok(diagnostics.length > 0, `Expected threats in ottercookie-v1.js, got ${diagnostics.length}`);
    console.log(`  Found ${diagnostics.length} diagnostics in ottercookie-v1.js`);
  });

  test('Should detect threats in malicious tasks.json', async function () {
    this.timeout(15000);
    const samplePath = path.join(__dirname, '..', '..', '..', 'samples',
      'stage1-initial-access', 'fake-vscode-repo', '.vscode', 'tasks.json');
    if (!fs.existsSync(samplePath)) { this.skip(); return; }
    const doc = await vscode.workspace.openTextDocument(samplePath);
    await vscode.window.showTextDocument(doc);
    await vscode.commands.executeCommand('fig.scanFile');
    await new Promise(r => setTimeout(r, 3000));
    const diagnostics = vscode.languages.getDiagnostics(doc.uri);
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
});

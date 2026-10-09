const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const { Recorder, REQUIRED, classifyTrust, requireDialog, exitCode, CdpClient, DASHBOARD_TITLE, validWorkspaceScan, snapshotStore } = require('../../scripts/test-installed-gui-acceptance');
const script = path.resolve(__dirname, '../../scripts/test-installed-gui-acceptance.js');
const withRecorder = run => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'fig-harness-negative-'));
  try { run(new Recorder(directory), directory); } finally { fs.rmSync(directory, { recursive: true, force: true }); }
};
suite('Installed GUI harness evidence gates', () => {
  for (const toast of ['FIG: 0 reported finding(s); 0 files scanned, 0 skipped, 0 error(s).',
    'FIG: 1 reported finding(s); 1 files scanned, 0 skipped, 1 error(s).',
    'FIG: 0 reported finding(s); 1 files scanned, 0 skipped, 0 error(s).',
    'FIG: 1 reported finding(s); 1 files scanned, 1 skipped, 0 error(s).', 'activation only', null]) {
    test(`scan evidence rejects incomplete or empty work: ${toast}`, () => assert.equal(validWorkspaceScan(toast), false));
  }
  test('one positively scanned inert fixture with no errors/skips is required', () =>
    assert.equal(validWorkspaceScan('FIG: 2 reported finding(s); 1 files scanned, 0 skipped, 0 error(s). A scan is not a safety guarantee.'), true));
  test('cancellation snapshot detects a copied payload/manifest even with original retained', () => withRecorder((_recorder, directory) => {
    const store = path.join(directory, 'store'); fs.mkdirSync(store);
    const before = snapshotStore(store);
    fs.writeFileSync(path.join(store, 'manifest.json'), '{"files":[{"id":"copied"}]}');
    fs.mkdirSync(path.join(store, 'copied')); fs.writeFileSync(path.join(store, 'copied/payload'), 'copy');
    assert.notDeepEqual(snapshotStore(store), before);
  }));
  test('read-only store snapshot preserves absent and existing store state', () => withRecorder((_recorder, directory) => {
    const store = path.join(directory, 'store'); assert.deepEqual(snapshotStore(store), []); assert(!fs.existsSync(store));
    fs.mkdirSync(store); fs.writeFileSync(path.join(store, 'manifest.json'), '{"files":[]}');
    const before = snapshotStore(store); assert.deepEqual(snapshotStore(store), before);
    fs.writeFileSync(path.join(store, 'manifest.json'), '{"files":[1]}'); assert.notDeepEqual(snapshotStore(store), before);
  }));
  test('dashboard gate matches the unchanged product tab title', () => {
    const source = fs.readFileSync(path.resolve(__dirname, '../../src/providers/dashboard-panel.ts'), 'utf8');
    assert.equal(DASHBOARD_TITLE, 'FIG Security Dashboard');
    assert(source.includes("'" + DASHBOARD_TITLE + "'"));
  });
  for (const value of [null, undefined, {}, { statusText: null }, { editorText: '', statusText: null },
    { editorText: 'You trust the following folders', statusText: null },
    { editorText: 'You trust this folder', statusText: 'Restricted Mode' },
    { editorText: 'You are in Restricted Mode', statusText: null }]) {
    test(`unknown/conflicting trust cannot pass: ${JSON.stringify(value)}`, () => assert.equal(classifyTrust(value), 'unknown'));
  }
  test('positive trusted and restricted editor observations are required', () => {
    assert.equal(classifyTrust({ editorText: 'You trust this folder', statusText: null }), 'trusted');
    assert.equal(classifyTrust({ editorText: 'You are in Restricted Mode', statusText: 'Restricted Mode' }), 'restricted');
  });
  for (const value of [null, { message: 'Different dialog', buttons: ['Quarantine file'] }, { message: 'Move this file to quarantine?', buttons: ['Cancel'] }]) {
    test(`missing dialog/action cannot count as cancellation: ${JSON.stringify(value)}`, () =>
      assert.throws(() => requireDialog(value, 'Move this file to quarantine?', 'Quarantine file')));
  }
  test('actual dialog and action satisfy the UI precondition', () =>
    assert.doesNotThrow(() => requireDialog({ message: 'Move this file to quarantine?', buttons: ['Quarantine file', 'Cancel'] }, 'Move this file to quarantine?', 'Quarantine file')));
  test('FAIL is saved and throws; remaining checks stay NOT_RUN', () => withRecorder((recorder, directory) => {
    assert.throws(() => recorder.check(REQUIRED[0], false, { actual: false }));
    const saved = JSON.parse(fs.readFileSync(path.join(directory, 'RESULT.json')));
    assert.equal(saved.checks[0].status, 'FAIL'); assert(saved.checks.slice(1).every(check => check.status === 'NOT_RUN'));
    assert.equal(exitCode(saved), 1);
  }));
  test('truthy non-boolean values cannot manufacture PASS', () => withRecorder(recorder => {
    assert.throws(() => recorder.check(REQUIRED[0], 'PASS', {})); assert.equal(exitCode(recorder.result), 1);
  }));
  test('missing, skipped, failed and fatal checks cannot exit zero', () => {
    const complete = { checks: REQUIRED.map(id => ({ id, status: 'PASS' })) };
    assert.equal(exitCode(complete), 0);
    for (const status of ['FAIL', 'NOT_RUN', 'PARTIAL', 'BLOCKED']) {
      const checks = complete.checks.map((check, i) => i ? check : { ...check, status }); assert.equal(exitCode({ checks }), 1);
    }
    assert.equal(exitCode({ checks: complete.checks.slice(1) }), 1);
    assert.equal(exitCode({ ...complete, error: { message: 'fatal' } }), 1);
  });
  test('duplicate screenshot bytes cannot support distinct UI transitions', () => withRecorder(recorder => {
    recorder.screenshot('apply', Buffer.from('synthetic screenshot bytes'), { observed: 'apply' });
    assert.throws(() => recorder.screenshot('undo', Buffer.from('synthetic screenshot bytes'), { observed: 'undo' }), /Duplicate screenshot/);
    assert.equal(recorder.result.screenshots.length, 1);
  }));
  test('screenshots retain hash, timestamp and observed state without overwriting', () => withRecorder((recorder, directory) => {
    recorder.screenshot('apply', Buffer.from('first'), { observed: 'apply' });
    recorder.screenshot('undo', Buffer.from('second'), { observed: 'undo' });
    const [first, second] = recorder.result.screenshots;
    assert.notEqual(first.sha256, second.sha256); assert(first.at && second.at);
    assert.equal(fs.readFileSync(path.join(directory, first.file), 'utf8'), 'first');
    assert.throws(() => recorder.screenshot('apply', Buffer.from('third'), { observed: 'different' }), /EEXIST/);
  }));
  test('CDP evaluation errors propagate instead of becoming null trust evidence', async () => {
    const client = new CdpClient('unused'); client.call = async () => ({ exceptionDetails: { text: 'bad selector' }, result: { value: null } });
    await assert.rejects(() => client.evaluate('invalid selector'), /evaluation failed/);
  });
  test('CLI uses the evidence result as its process exit status', () => {
    // Instrument only the runner boundary, without launching an editor or evaluating fixtures.
    for (const status of ['PASS', 'FAIL', 'NOT_RUN']) {
      const child = spawnSync(process.execPath, ['-e', `
        const fs=require('fs'),vm=require('vm'); const filename=process.argv[1];
        let source=fs.readFileSync(filename,'utf8');
        const boundary=source.lastIndexOf('if (require.main === module)');
        source=source.slice(boundary,source.indexOf('module.exports',boundary));
        const module={}; const req=()=>{};req.main=module;
        const results={checks:${JSON.stringify(REQUIRED)}.map(id=>({id,status:process.argv[2]}))};
        const real=require(filename);
        vm.runInNewContext(source,{require:req,module,__dirname:'.',path:require('path'),fs:{mkdirSync(){}},runInstalledGuiAcceptance:async()=>results,exitCode:real.exitCode,console:{log(){},error(){}},process});
      `, script, status], { encoding: 'utf8' });
      assert.equal(child.status, status === 'PASS' ? 0 : 1, child.stderr);
    }
  });
  test('obsolete duplicate helper is absent from active scripts and npm entry points', () => {
    assert(!fs.existsSync(path.resolve(__dirname, '../../scripts/test-installed-vsix-acceptance.js')));
    assert(!JSON.stringify(require('../../package.json').scripts).includes('test-installed-vsix-acceptance'));
  });
  test('driver has no sandbox bypass, dangerous auto-run command, or direct product fallback', () => {
    const source = fs.readFileSync(script, 'utf8');
    assert(!source.includes('--no-sandbox')); assert(!/curl.*\|\s*bash/.test(source));
    assert(!/require\([^\n]*quarantine-manager/.test(source));
    assert(!source.includes('qm.quarantine') && !source.includes('qm.restore'));
    assert(source.includes("command: 'echo inert-review-fixture'"));
    assert(source.includes("'task.allowAutomaticTasks': 'off'"));
    assert(source.includes('--untracked-files=all'));
    assert(!source.includes('--untracked-files=no')); 
  });
});

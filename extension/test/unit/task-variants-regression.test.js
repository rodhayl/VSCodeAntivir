const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { parse } = require('jsonc-parser');
const outputRoot = process.env.FIG_TASK_TEST_OUT || path.resolve(__dirname, '../../out');
const { TaskInterceptor } = require(path.join(outputRoot, 'interceptors/task-interceptor'));
const { runVscodeTaskEngine } = require(path.join(outputRoot, 'scanner/engines/vscode-task-engine'));
const { Scanner } = require(path.join(outputRoot, 'scanner/scanner'));
const { createHost } = require('../helpers/extension-host-stub');
// Every command below is inert fixture text. No task, shell or sample is executed.
async function fixture(configuration, run) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'fig-task-variants-'));
  const file = path.join(root, 'tasks.json');
  const original = typeof configuration === 'string' ? configuration : JSON.stringify(configuration, null, 2);
  fs.writeFileSync(file, original);
  const logs = [];
  const interceptor = new TaskInterceptor({ appendLine: line => logs.push(line) });
  try { await run({ root, file, original, logs, interceptor, review: await interceptor.scanAndBlock(file) }); }
  finally { fs.rmSync(root, { recursive: true, force: true }); }
}
function flagged(review, original) {
  assert(review.hasThreats, 'configuration review must inspect the executable text');
  assert(runVscodeTaskEngine(original, 'tasks.json').some(t => t.ruleId === 'vscode-task-piped-exec'), 'scanner must inspect the same representation');
}
suite('R1 task variants regression', () => {
  for (const platform of ['windows', 'linux', 'osx']) {
    test(`inspects ${platform} object command and quoted arguments`, () => fixture({ tasks: [{ label: 'variant', command: 'echo base', [platform]: { command: { value: 'echo', quoting: 'strong' }, args: [{ value: 'fixture | sh', quoting: 'weak' }] } }] }, async ({ review, original, file }) => {
      flagged(review, original);
      assert(review.threats.some(t => t.variant === platform));
      assert.strictEqual(fs.readFileSync(file, 'utf8'), original);
      assert(!fs.existsSync(file + '.fig-backup'));
    }));
    test(`inspects inherited global ${platform} command/args`, () => fixture({ type: 'shell', command: 'echo', [platform]: { args: [{ value: 'global fixture | sh', quoting: 'escape' }] }, tasks: [{ label: 'inherits' }] }, async ({ review, original }) => flagged(review, original)));
    test(`inspects tasks defined in global ${platform} scope`, () => fixture({ [platform]: { tasks: [{ label: 'platform task', command: 'echo fixture | sh' }] } }, async ({ review, original }) => flagged(review, original)));
  }
  test('inspects object-valued command and args in base task', () => fixture({ tasks: [{ command: { value: 'echo fixture | sh', quoting: 'strong' }, args: [{ value: 'bit.ly/inert', quoting: 'weak' }] }] }, async ({ review, original }) => {
    flagged(review, original); assert(review.threats.some(t => t.type === 'url-shortener'));
  }));
  test('inspects global and local arguments concatenated by an inherited command', () => fixture({ type: 'shell', command: 'echo', args: ['fixture |'], tasks: [{ label: 'inherits', args: ['sh'] }] }, async ({ review, original }) => flagged(review, original)));
  test('global platform task shadowing cannot leave the effective task intact', () => fixture({ tasks: [{ label: 'shadowed', type: 'shell', command: 'echo fixture | sh' }], windows: { tasks: [{ label: 'shadowed', type: 'shell', command: 'echo WINDOWS_EFFECTIVE_REMAINS' }] } }, async ({ interceptor, review, file, original }) => {
    assert(review.remediationError); assert.strictEqual(await interceptor.applyBlock(review), false);
    assert.strictEqual(fs.readFileSync(file, 'utf8'), original); assert(!fs.existsSync(file + '.fig-backup'));
  }));
  test('legacy inherited shell settings are explicitly refused', () => fixture({ isShellCommand: { executable: 'fixture-shell' }, options: {}, tasks: [{ command: 'echo fixture | sh' }] }, async ({ interceptor, review, file, original }) => {
    assert(review.remediationError); assert.strictEqual(await interceptor.applyBlock(review), false); assert.strictEqual(fs.readFileSync(file, 'utf8'), original);
  }));
  test('legacy task version is explicitly refused for remediation', () => fixture({ version: '0.1.0', tasks: [{ command: 'echo fixture | sh' }] }, async ({ interceptor, review, file, original }) => {
    assert(review.remediationError); assert.strictEqual(await interceptor.applyBlock(review), false); assert.strictEqual(fs.readFileSync(file, 'utf8'), original);
  }));
  test('inspects standalone global command without tasks array', () => fixture({ type: 'shell', command: { value: 'echo fixture | sh', quoting: 'strong' } }, async ({ review, original }) => flagged(review, original)));
  test('neutralizes every shell variant and dependency, keeps unrelated task and restores exact JSONC', () => fixture('// retained comment\n' + JSON.stringify({ tasks: [
    { label: 'flagged', type: 'shell', command: 'echo fixture | sh', args: ['base'], dependsOn: ['dependency'], runOptions: { runOn: 'folderOpen' }, windows: { command: 'echo WIN_REMAINS', args: ['WIN_ARG'], dependsOn: ['dependency'] }, linux: { command: 'echo LINUX_REMAINS' }, osx: { command: { value: 'echo MAC_REMAINS', quoting: 'strong' } } },
    { label: 'dependency', type: 'shell', command: 'echo unrelated' },
  ] }), async ({ interceptor, review, file, original }) => {
    assert(await interceptor.applyBlock(review));
    const changed = fs.readFileSync(file, 'utf8'), data = parse(changed), task = data.tasks[0];
    for (const value of [task, task.windows, task.linux, task.osx]) {
      assert.strictEqual(value.command, 'echo Task disabled after review by FakeInterviewGuard');
      assert.deepStrictEqual(value.args, []); assert.deepStrictEqual(value.dependsOn, []);
      assert.strictEqual(value.runOptions.runOn, 'default');
    }
    assert.deepStrictEqual(data.tasks[1], { label: 'dependency', type: 'shell', command: 'echo unrelated' });
    assert(changed.includes('// retained comment')); assert.strictEqual(fs.readFileSync(file + '.fig-backup', 'utf8'), original);
    assert(!(await interceptor.scanAndBlock(file)).hasThreats);
    assert.strictEqual(await interceptor.applyBlock(review), false, 'repeat application must not overwrite recovery state');
    assert(await interceptor.restoreOriginal(file)); assert.strictEqual(fs.readFileSync(file, 'utf8'), original);
  }));
  test('startup-only change disables all runOn variants without claiming command neutralization', () => fixture({ tasks: [{ label: 'startup', command: 'echo preserved', dependsOn: ['build'], runOptions: { runOn: 'folderOpen' }, windows: { command: 'echo WINDOWS_PRESERVED', runOptions: { runOn: 'folderOpen' } } }] }, async ({ interceptor, review, file }) => {
    assert(await interceptor.applyBlock(review)); const task = parse(fs.readFileSync(file, 'utf8')).tasks[0];
    assert.strictEqual(task.command, 'echo preserved'); assert.strictEqual(task.windows.command, 'echo WINDOWS_PRESERVED');
    assert.strictEqual(task.runOptions.runOn, 'default'); assert.strictEqual(task.windows.runOptions.runOn, 'default');
  }));
  const unsupported = [
    ['process task', { tasks: [{ type: 'process', command: 'echo fixture | sh' }] }],
    ['custom provider', { tasks: [{ type: 'npm', command: 'echo fixture | sh', script: 'fixture' }] }],
    ['custom shell', { tasks: [{ type: 'shell', command: 'echo fixture | sh', options: { shell: { executable: 'fixture-shell', args: ['fixture'] } } }] }],
    ['OS custom shell', { tasks: [{ command: 'echo fixture | sh', windows: { options: { shell: { executable: 'fixture-shell' } } } }] }],
    ['inherited custom shell', { options: { shell: { executable: 'fixture-shell' } }, tasks: [{ command: 'echo fixture | sh' }] }],
    ['global command', { command: 'echo global | sh', tasks: [{ label: 'inherits' }] }],
    ['OS process variant', { tasks: [{ command: 'echo fixture | sh', linux: { type: 'process', command: 'fixture-process' } }] }],
  ];
  for (const [name, configuration] of unsupported) {
    test(`refuses ${name} visibly before making any change`, () => fixture(configuration, async ({ interceptor, review, file, original }) => {
      assert(review.hasThreats); assert(review.remediationError, 'review must explain unsupported remediation before approval');
      assert.strictEqual(await interceptor.applyBlock(review), false);
      assert.strictEqual(fs.readFileSync(file, 'utf8'), original); assert(!fs.existsSync(file + '.fig-backup'));
    }));
  }
  test('mixed supported/unsupported review refuses atomically', () => fixture({ tasks: [{ type: 'shell', command: 'echo fixture | sh' }, { type: 'process', command: 'echo fixture | sh' }] }, async ({ interceptor, review, file, original }) => {
    assert.strictEqual(await interceptor.applyBlock(review), false); assert.strictEqual(fs.readFileSync(file, 'utf8'), original); assert(!fs.existsSync(file + '.fig-backup'));
  }));
  test('malformed object command cannot be silently remediated', () => fixture({ tasks: [{ command: { value: 42, quoting: 'strong' }, runOptions: { runOn: 'folderOpen' } }] }, async ({ interceptor, review, file, original }) => {
    assert(review.error || review.remediationError); assert.strictEqual(await interceptor.applyBlock(review), false); assert.strictEqual(fs.readFileSync(file, 'utf8'), original);
  }));
  test('notification exposes unsupported reason and no apply action', () => fixture(unsupported[0][1], async ({ root, review, file, original }) => {
    const host = createHost(root); const { BlockingNotificationService } = host.load(path.join(outputRoot, 'notifications/blocking-notification'));
    await new BlockingNotificationService({ appendLine() {} }).notifyTaskBlocked(review);
    const message = host.messages[0]; assert(message.options.detail.includes(review.remediationError));
    assert(!message.choices.some(choice => /Disable flagged tasks|Apply reviewed task changes/.test(choice)));
    assert.strictEqual(fs.readFileSync(file, 'utf8'), original);
  }));
  test('dismissed supported review remains byte-identical and creates no backup', () => fixture({ tasks: [{ command: 'echo fixture | sh', linux: { command: 'echo linux' } }] }, async ({ root, review, interceptor, file, original }) => {
    const host = createHost(root); const { BlockingNotificationService } = host.load(path.join(outputRoot, 'notifications/blocking-notification'));
    const service = new BlockingNotificationService({ appendLine() {} }); service.setTaskInterceptor(interceptor); await service.notifyTaskBlocked(review);
    assert.strictEqual(fs.readFileSync(file, 'utf8'), original); assert(!fs.existsSync(file + '.fig-backup'));
  }));
});

suite('R1 unsupported task input is an incomplete scan', () => {
  for (const value of [
    { tasks: [{ command: { value: 42, quoting: 'strong' } }] },
    { tasks: [{ command: 'echo', args: [42] }] },
    { tasks: [{ command: 'echo', windows: null }] },
    { linux: { tasks: [null] } },
  ]) test(JSON.stringify(value), () => {
    const result = new Scanner().scanFile('tasks.json', JSON.stringify(value));
    assert.strictEqual(result.status, 'error');assert(result.detail.includes('Configuration parse failed'));
  });
});

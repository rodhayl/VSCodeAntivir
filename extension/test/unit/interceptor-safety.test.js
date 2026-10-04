const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { parse } = require('jsonc-parser');
const { TaskInterceptor } = require('../../out/interceptors/task-interceptor');
const { NpmScriptInterceptor } = require('../../out/interceptors/npm-script-interceptor');
const { GitConfigInterceptor } = require('../../out/interceptors/git-config-interceptor');
const { FileChange } = require('../../out/safety/file-change');
const output = { appendLine() {} };
async function withDirectory(run) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'fig-review-'));
  const write = (relative, content) => { const p = path.join(root, relative); fs.mkdirSync(path.dirname(p), { recursive: true }); fs.writeFileSync(p, content); return p; };
  try { await run(root, write); } finally { fs.rmSync(root, { recursive: true, force: true }); }
}
suite('Explicit interceptor safety', () => {
  test('JSONC inspection never mutates; explicit args remediation is verified and reversible', () => withDirectory(async (_root, write) => {
    const original = '// ordinary comment\n{"tasks":[{"label":"Example","command":"echo","args":["hello | sh"],}],}';
    const file = write('.vscode/tasks.json', original); const interceptor = new TaskInterceptor(output);
    const review = await interceptor.scanAndBlock(file);
    assert(review.hasThreats); assert(!review.blocked); assert.strictEqual(fs.readFileSync(file, 'utf8'), original);
    assert(await interceptor.applyBlock(review));
    const changed = fs.readFileSync(file, 'utf8'); assert(changed.includes('// ordinary comment'));
    assert.deepStrictEqual(parse(changed).tasks[0].args, []);
    assert(!(await interceptor.scanAndBlock(file)).hasThreats);
    assert(await interceptor.restoreOriginal(file)); assert.strictEqual(fs.readFileSync(file, 'utf8'), original);
  }));
  test('changed task after review is refused without backup or overwrite', () => withDirectory(async (_root, write) => {
    const file = write('tasks.json', '{"tasks":[{"command":"echo","runOptions":{"runOn":"folderOpen"}}]}');
    const i = new TaskInterceptor(output); const review = await i.scanAndBlock(file);
    fs.writeFileSync(file, '{"tasks":[]}'); assert.strictEqual(await i.applyBlock(review), false);
    assert.strictEqual(fs.readFileSync(file, 'utf8'), '{"tasks":[]}'); assert(!fs.existsSync(file + '.fig-backup'));
  }));
  test('task symlink cannot mutate another directory', function () {
    if (process.platform === 'win32') this.skip();
    return withDirectory(async (root, write) => {
      const content = '{"tasks":[{"command":"echo","runOptions":{"runOn":"folderOpen"}}]}';
      const outside = write('sibling/tasks.json', content); const link = path.join(root, 'tasks.json'); fs.symlinkSync(outside, link);
      const i = new TaskInterceptor(output); const review = await i.scanAndBlock(link);
      assert(review.error); assert.strictEqual(await i.applyBlock(review), false); assert.strictEqual(fs.readFileSync(outside, 'utf8'), content);
    });
  });
  for (const initial of ['ignore-scripts=false\n', '# ignore-scripts is optional\n']) {
    test(`npm inspection does not claim a block for ${initial.trim()}`, () => withDirectory(async (_root, write) => {
      const pkg = write('package.json', '{"scripts":{"prepare":"node benign-build.js"}}'); const npmrc = write('.npmrc', initial);
      const i = new NpmScriptInterceptor(output); const review = await i.scanAndBlock(pkg);
      assert(review.hasThreats); assert(!review.blocked); assert(!review.npmrcModified); assert.strictEqual(fs.readFileSync(npmrc, 'utf8'), initial);
      assert(await i.applyBlock(review)); assert(fs.readFileSync(npmrc, 'utf8').endsWith('ignore-scripts=true\n'));
      assert(await i.removeBlock(pkg)); assert.strictEqual(fs.readFileSync(npmrc, 'utf8'), initial);
    }));
  }
  test('pre-existing user npm guard is never claimed or removed', () => withDirectory(async (_root, write) => {
    const pkg = write('package.json', '{"scripts":{"prepare":"node benign-build.js"}}'); const npmrc = write('.npmrc', 'ignore-scripts=true\n');
    const i = new NpmScriptInterceptor(output); const review = await i.scanAndBlock(pkg);
    assert.strictEqual(await i.applyBlock(review), false); assert.strictEqual(await i.removeBlock(pkg), false);
    assert.strictEqual(fs.readFileSync(npmrc, 'utf8'), 'ignore-scripts=true\n');
  }));
  test('git inspection is read-only; explicit change preserves new edits on undo', () => withDirectory(async (root, write) => {
    const original = '[core]\nfsmonitor = true\n'; const file = write('.git/config', original);
    const i = new GitConfigInterceptor(output); const review = await i.interceptWorkspace({ uri: { fsPath: root }, name: 'fixture' });
    assert(review.hasThreats); assert(!review.blocked); assert.strictEqual(fs.readFileSync(file, 'utf8'), original);
    assert(await i.applyBlock(review)); fs.appendFileSync(file, '# new user edit\n');
    assert.strictEqual(await i.restoreGitConfig(file), false); assert(fs.readFileSync(file, 'utf8').endsWith('# new user edit\n'));
  }));
  test('an unverified existing backup prevents overwriting it', () => withDirectory(async (_root, write) => {
    const file = write('data.txt', 'before'); const backup = write('data.txt.fig-backup', 'other backup');
    assert.throws(() => new FileChange().apply(file, 'before', 'after'));
    assert.strictEqual(fs.readFileSync(file, 'utf8'), 'before'); assert.strictEqual(fs.readFileSync(backup, 'utf8'), 'other backup');
  }));
  test('failed replacement retains original and recoverable backup', () => withDirectory(async (_root, write) => {
    const file = write('data.txt', 'before'); const rename = fs.renameSync;
    fs.renameSync = (a,b) => { if (b === file + '.fig-backup') throw new Error('synthetic rename failure'); return rename(a,b); };
    try { assert.throws(() => new FileChange().apply(file, 'before', 'after')); } finally { fs.renameSync = rename; }
    assert.strictEqual(fs.readFileSync(file, 'utf8'), 'before'); assert.strictEqual(fs.readFileSync(file + '.fig-backup', 'utf8'), 'before');
  }));
  test('a source replaced immediately before capture retains the latest bytes', () => withDirectory(async (_root, write) => {
    const file = write('data.txt', 'before'); const rename = fs.renameSync;
    fs.renameSync = (a,b) => { if (a === file) fs.writeFileSync(file, 'newer work'); return rename(a,b); };
    try { assert.throws(() => new FileChange().apply(file, 'before', 'after')); } finally { fs.renameSync = rename; }
    assert.strictEqual(fs.readFileSync(file, 'utf8'), 'newer work');
    assert.strictEqual(fs.readFileSync(file + '.fig-backup', 'utf8'), 'newer work');
  }));
  test('undo captures a last-moment writer rather than deleting its work', () => withDirectory(async (_root, write) => {
    const file = write('data.txt', 'before'); const change = new FileChange(); change.apply(file, 'before', 'after');
    const rename = fs.renameSync;
    fs.renameSync = (a,b) => { if (a === file) fs.writeFileSync(file, 'newer work'); return rename(a,b); };
    try { assert.throws(() => change.restore(file)); } finally { fs.renameSync = rename; }
    assert.strictEqual(fs.readFileSync(file, 'utf8'), 'newer work');
  }));
  test('same-session undo restores, but another instance cannot adopt the backup', () => withDirectory(async (_root, write) => {
    const file = write('data.txt', 'before'); const first = new FileChange(); assert(first.apply(file, 'before', 'after'));
    assert.strictEqual(new FileChange().restore(file), false); assert(first.restore(file)); assert.strictEqual(fs.readFileSync(file, 'utf8'), 'before');
  }));
  test('non-UTF-8 originals are refused before creating a backup or changing bytes', () => withDirectory(async (_root, write) => {
    const original=Buffer.concat([Buffer.from('# caf'),Buffer.from([0xe9]),Buffer.from('\n[core]\nfsmonitor = true\n')]);
    const file=write('config',original);
    assert.throws(()=>new FileChange().apply(file,original.toString('utf8'),'# reviewed configuration\n'));
    assert(fs.readFileSync(file).equals(original));assert(!fs.existsSync(file+'.fig-backup'));
  }));
  test('undo refuses a binary-distinct backup with the same decoded text', () => withDirectory(async (_root, write) => {
    const file=write('data.txt','before \ufffd');const change=new FileChange();assert(change.apply(file,'before \ufffd','after'));
    const changed=Buffer.concat([Buffer.from('before '),Buffer.from([0xe9])]);fs.writeFileSync(file+'.fig-backup',changed);
    assert.strictEqual(change.restore(file),false);
    assert.strictEqual(fs.readFileSync(file,'utf8'),'after');assert(fs.readFileSync(file+'.fig-backup').equals(changed));
  }));
  test('Git remediation reports unsupported encoding and retains the exact original', () => withDirectory(async (root, write) => {
    const original=Buffer.concat([Buffer.from('# caf'),Buffer.from([0xe9]),Buffer.from('\n[core]\nfsmonitor = true\n')]);
    const file=write('.git/config',original);const logs=[];const interceptor=new GitConfigInterceptor({appendLine:line=>logs.push(line)});
    const review=await interceptor.interceptWorkspace({uri:{fsPath:root},name:'fixture'});assert(review.hasThreats);
    assert.strictEqual(await interceptor.applyBlock(review),false);assert(fs.readFileSync(file).equals(original));
    assert(!fs.existsSync(file+'.fig-backup'));assert(logs.some(line=>line.includes('not valid UTF-8')));
  }));
  test('captured binary-distinct source is preserved even when decoded text matches', () => withDirectory(async (_root, write) => {
    const file=write('data.txt','before \ufffd');const newer=Buffer.concat([Buffer.from('before '),Buffer.from([0xe9])]);const rename=fs.renameSync;
    fs.renameSync=(a,b)=>{if(a===file)fs.writeFileSync(file,newer);return rename(a,b);};
    try{assert.throws(()=>new FileChange().apply(file,'before \ufffd','after'));}finally{fs.renameSync=rename;}
    assert(fs.readFileSync(file).equals(newer));assert(fs.readFileSync(file+'.fig-backup').equals(newer));
  }));
  test('undo retains its backup when restored bytes cannot be verified', () => withDirectory(async (_root, write) => {
    const file=write('data.txt','before');const change=new FileChange();assert(change.apply(file,'before','after'));const link=fs.linkSync;
    fs.linkSync=(a,b)=>{link(a,b);if(b===file)fs.writeFileSync(file,'new unrelated work');};
    try{assert.throws(()=>change.restore(file));}finally{fs.linkSync=link;}
    assert.strictEqual(fs.readFileSync(file,'utf8'),'new unrelated work');assert.strictEqual(fs.readFileSync(file+'.fig-backup','utf8'),'before');
  }));
});

const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { QuarantineManager } = require('../../out/quarantine/quarantine-manager');

suite('Quarantine safety', () => {
  const output = { appendLine() {} };
  async function fixture(run) {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'fig-safe-'));
    const store = path.join(root, 'store');
    const source = path.join(root, 'benign.txt');
    fs.writeFileSync(source, 'benign fixture');
    try { await run({ root, store, source, manager: new QuarantineManager(output, store) }); }
    finally { fs.rmSync(root, { recursive: true, force: true }); }
  }
  test('roundtrip preserves original bytes and restrictive mode', () => fixture(async ({ manager, source }) => {
    fs.chmodSync(source, 0o600);
    const entry = await manager.quarantine(source, []);
    assert(entry); assert(!fs.existsSync(source));
    if (process.platform !== 'win32') assert.strictEqual(fs.statSync(entry.quarantinePath).mode & 0o777, 0o600);
    assert(await manager.restore(entry.id));
    assert.strictEqual(fs.readFileSync(source, 'utf8'), 'benign fixture');
    if (process.platform !== 'win32') assert.strictEqual(fs.statSync(source).mode & 0o777, 0o600);
  }));
  test('restore refuses a recreated original and retains recovery payload', () => fixture(async ({ manager, source }) => {
    const entry = await manager.quarantine(source, []);
    fs.writeFileSync(source, 'new work');
    assert.strictEqual(await manager.restore(entry.id), false);
    assert.strictEqual(fs.readFileSync(source, 'utf8'), 'new work');
    assert(fs.existsSync(entry.quarantinePath)); assert.strictEqual(manager.getCount(), 1);
  }));
  test('restore refuses a destination symlink without touching its target', function () {
    if (process.platform === 'win32') this.skip();
    return fixture(async ({ manager, source, root }) => {
      const entry = await manager.quarantine(source, []);
      const sibling = path.join(root, 'sibling.txt'); fs.writeFileSync(sibling, 'new work');
      fs.symlinkSync(sibling, source);
      assert.strictEqual(await manager.restore(entry.id), false);
      assert.strictEqual(fs.readFileSync(sibling, 'utf8'), 'new work'); assert(fs.existsSync(entry.quarantinePath));
    });
  });
  test('independent managers retain both entries and independent restores', () => fixture(async ({ manager, source, store, root }) => {
    const other = new QuarantineManager(output, store);
    const second = path.join(root, 'second.txt'); fs.writeFileSync(second, 'second');
    const a = await manager.quarantine(source, []); const b = await other.quarantine(second, []);
    assert(a && b); assert.strictEqual(new QuarantineManager(output, store).getCount(), 2);
    assert(await manager.restore(a.id)); assert.strictEqual(other.getCount(), 1);
    assert(await other.restore(b.id)); assert.strictEqual(manager.getCount(), 0);
  }));
  test('failed first metadata commit never removes source', () => fixture(async ({ manager, source, store }) => {
    const rename = fs.renameSync;
    fs.renameSync = (from, to) => { if (to === path.join(store, 'manifest.json')) throw new Error('Synthetic metadata failure'); return rename(from, to); };
    try { assert.strictEqual(await manager.quarantine(source, []), null); } finally { fs.renameSync = rename; }
    assert.strictEqual(fs.readFileSync(source, 'utf8'), 'benign fixture');
    assert.strictEqual(new QuarantineManager(output, store).getCount(), 0);
  }));
  test('failed final metadata commit leaves a durable recovery record after source removal', () => fixture(async ({ manager, source, store }) => {
    const rename = fs.renameSync; let commits = 0;
    fs.renameSync = (from, to) => { if (to === path.join(store, 'manifest.json') && ++commits === 2) throw new Error('Synthetic final commit failure'); return rename(from, to); };
    try { assert.strictEqual(await manager.quarantine(source, []), null); } finally { fs.renameSync = rename; }
    assert(!fs.existsSync(source));
    const restarted = new QuarantineManager(output, store); const entries = restarted.getQuarantinedFiles();
    assert.strictEqual(entries.length, 1); assert(await restarted.restore(entries[0].id));
    assert.strictEqual(fs.readFileSync(source, 'utf8'), 'benign fixture');
  }));
  test('equal content, basename and clock produce unique recoverable entries', () => fixture(async ({ manager, root }) => {
    const a = path.join(root, 'a', 'same.txt'), b = path.join(root, 'b', 'same.txt');
    for (const p of [a,b]) { fs.mkdirSync(path.dirname(p)); fs.writeFileSync(p, 'same'); }
    const now = Date.now; Date.now = () => 123456;
    let first, second;
    try { first = await manager.quarantine(a, []); second = await manager.quarantine(b, []); } finally { Date.now = now; }
    assert(first && second); assert.notStrictEqual(first.id, second.id);
    assert(await manager.restore(first.id)); assert(await manager.restore(second.id));
  }));
  test('corrupt manifest blocks mutation and is never overwritten', () => fixture(async ({ manager, source, store }) => {
    const manifest = path.join(store, 'manifest.json'); fs.writeFileSync(manifest, '{broken');
    assert.strictEqual(await manager.quarantine(source, []), null);
    assert(fs.existsSync(source)); assert.strictEqual(fs.readFileSync(manifest, 'utf8'), '{broken');
  }));
  test('forged outside payload path cannot delete an unrelated file', () => fixture(async ({ manager, source, store, root }) => {
    const entry = await manager.quarantine(source, []);
    const sibling = path.join(root, 'outside.txt'); fs.writeFileSync(sibling, 'retain');
    const manifestPath = path.join(store, 'manifest.json'); const data = JSON.parse(fs.readFileSync(manifestPath));
    data.files[0].quarantinePath = sibling; fs.writeFileSync(manifestPath, JSON.stringify(data));
    assert.strictEqual(await manager.deletePermanently(entry.id), false);
    assert.strictEqual(fs.readFileSync(sibling, 'utf8'), 'retain');
  }));
  test('payload tampering is refused without deleting the entry', () => fixture(async ({ manager, source }) => {
    const entry = await manager.quarantine(source, []); fs.writeFileSync(entry.quarantinePath, 'changed');
    assert.strictEqual(await manager.restore(entry.id), false); assert(!fs.existsSync(source)); assert.strictEqual(manager.getCount(), 1);
  }));
  test('busy store fails closed without removing source or someone else lock', () => fixture(async ({ manager, source, store }) => {
    const lock = path.join(store, '.mutation-lock'); fs.mkdirSync(lock);
    assert.strictEqual(await manager.quarantine(source, []), null); assert(fs.existsSync(source)); assert(fs.existsSync(lock));
  }));
  test('throwing observers and output channels cannot mask a committed result', () => fixture(async ({ store, source }) => {
    const manager = new QuarantineManager({ appendLine() { throw new Error('Disposed output'); } }, store);
    manager.setChangeHandler(() => { throw new Error('Disposed view'); });
    let refreshes = 0;
    const subscription = manager.addChangeHandler(() => { refreshes++; });
    const entry = await manager.quarantine(source, []);
    assert(entry); assert.strictEqual(refreshes, 1); assert(!fs.existsSync(source));
    subscription.dispose(); assert(await manager.restore(entry.id)); assert.strictEqual(refreshes, 1);
    assert.strictEqual(fs.readFileSync(source, 'utf8'), 'benign fixture');
  }));
  test('failed lock cleanup does not turn a committed result into a rejection', () => fixture(async ({ manager, source, store }) => {
    const remove = fs.rmdirSync;
    fs.rmdirSync = target => { if (target === path.join(store, '.mutation-lock')) throw new Error('Synthetic lock cleanup error'); return remove(target); };
    let entry;
    try { entry = await manager.quarantine(source, []); } finally { fs.rmdirSync = remove; }
    assert(entry); assert(!fs.existsSync(source)); assert(fs.existsSync(entry.quarantinePath));
    assert.strictEqual(await manager.restore(entry.id), false); assert(manager.getLastError().includes('busy'));
  }));
  test('source changes during metadata commit retain original and recovery copies', () => fixture(async ({ manager, source, store }) => {
    const rename = fs.renameSync; let commits = 0;
    fs.renameSync = (from, to) => {
      const result = rename(from, to);
      if (to === path.join(store, 'manifest.json') && ++commits === 1) fs.writeFileSync(source, 'new work');
      return result;
    };
    try { assert.strictEqual(await manager.quarantine(source, []), null); } finally { fs.renameSync = rename; }
    assert.strictEqual(fs.readFileSync(source, 'utf8'), 'new work');
    const [entry] = manager.getQuarantinedFiles(); assert(entry);
    assert.strictEqual(fs.readFileSync(entry.quarantinePath, 'utf8'), 'benign fixture');
  }));
  test('duplicate manifest IDs fail closed for restore and delete', () => fixture(async ({ manager, source, store }) => {
    const entry = await manager.quarantine(source, []);
    const file = path.join(store, 'manifest.json'); const manifest = JSON.parse(fs.readFileSync(file));
    manifest.files.push({ ...manifest.files[0] }); const bytes = JSON.stringify(manifest); fs.writeFileSync(file, bytes);
    assert.strictEqual(await manager.restore(entry.id), false); assert.strictEqual(await manager.deletePermanently(entry.id), false);
    assert.strictEqual(fs.readFileSync(file, 'utf8'), bytes); assert(fs.existsSync(entry.quarantinePath));
  }));
  test('the store cannot quarantine its own recovery artifacts', () => fixture(async ({ manager, source }) => {
    const entry = await manager.quarantine(source, []);
    assert.strictEqual(await manager.quarantine(entry.quarantinePath, []), null);
    assert(fs.existsSync(entry.quarantinePath)); assert.strictEqual(manager.getCount(), 1);
  }));
  test('snapshot identity is checked under the mutation lock', () => fixture(async ({ manager, source, store }) => {
    const entry = await manager.quarantine(source, []);
    const file = path.join(store, 'manifest.json'); const manifest = JSON.parse(fs.readFileSync(file));
    manifest.files[0].detectedAt = new Date(0).toISOString(); fs.writeFileSync(file, JSON.stringify(manifest));
    assert.strictEqual(await manager.restore(entry.id, entry), false);
    assert.strictEqual(await manager.deletePermanently(entry.id, entry), false);
    assert(!fs.existsSync(source)); assert(fs.existsSync(entry.quarantinePath));
  }));
  test('failed restore metadata commit retains destination and recoverable entry', () => fixture(async ({ manager, source, store }) => {
    const entry = await manager.quarantine(source, []); const rename = fs.renameSync;
    fs.renameSync = (from, to) => { if (to === path.join(store, 'manifest.json')) throw new Error('Synthetic restore commit failure'); return rename(from, to); };
    try { assert.strictEqual(await manager.restore(entry.id), false); } finally { fs.renameSync = rename; }
    assert.strictEqual(fs.readFileSync(source, 'utf8'), 'benign fixture');
    assert(fs.existsSync(entry.quarantinePath)); assert.strictEqual(manager.getCount(), 1);
    assert.strictEqual(await manager.restore(entry.id), false);
  }));
  test('failed restore write preserves the recovery copy and reports failure', () => fixture(async ({ manager, source }) => {
    const entry = await manager.quarantine(source, []); const write = fs.writeFileSync;
    fs.writeFileSync = (target, ...args) => { if (typeof target === 'number') throw new Error('Synthetic restore write failure'); return write(target, ...args); };
    try { assert.strictEqual(await manager.restore(entry.id), false); } finally { fs.writeFileSync = write; }
    assert(fs.existsSync(entry.quarantinePath)); assert.strictEqual(manager.getCount(), 1);
  }));
  test('restore recreates missing parent directories with original bytes', () => fixture(async ({ manager, root }) => {
    const directory = path.join(root, 'nested', 'child'); fs.mkdirSync(directory, { recursive: true });
    const source = path.join(directory, 'fixture.txt'); fs.writeFileSync(source, 'nested fixture');
    const entry = await manager.quarantine(source, []); fs.rmdirSync(directory); fs.rmdirSync(path.dirname(directory));
    assert(await manager.restore(entry.id)); assert.strictEqual(fs.readFileSync(source, 'utf8'), 'nested fixture');
  }));
  test('directory durability is established before capturing the source', function () {
    if (process.platform === 'win32') this.skip();
    return fixture(async ({ manager, source, store }) => {
      const sync = fs.fsyncSync, rename = fs.renameSync;
      let syncedDirectories = 0;
      fs.fsyncSync = fd => { if (fs.fstatSync(fd).isDirectory()) syncedDirectories++; return sync(fd); };
      fs.renameSync = (from, to) => { if (from === source) assert(syncedDirectories >= 2); return rename(from, to); };
      try { assert(await manager.quarantine(source, [])); } finally { fs.fsyncSync = sync; fs.renameSync = rename; }
      if (process.platform !== 'win32') {
        assert.strictEqual(fs.statSync(store).mode & 0o777, 0o700);
        assert.strictEqual(fs.statSync(path.join(store, 'manifest.json')).mode & 0o777, 0o600);
      }
    });
  });
  test('restore refuses a symlinked destination parent', function () {
    if (process.platform === 'win32') this.skip();
    return fixture(async ({ manager, root }) => {
      const parent = path.join(root, 'parent'); const outside = path.join(root, 'outside');
      fs.mkdirSync(parent); fs.mkdirSync(outside);
      const source = path.join(parent, 'fixture.txt'); fs.writeFileSync(source, 'original');
      const entry = await manager.quarantine(source, []); fs.rmdirSync(parent); fs.symlinkSync(outside, parent);
      assert.strictEqual(await manager.restore(entry.id), false);
      assert(!fs.existsSync(path.join(outside, 'fixture.txt'))); assert(fs.existsSync(entry.quarantinePath));
    });
  });
  test('recovery reads surface corrupt-store errors and clear them after repair', () => fixture(async ({ manager, store }) => {
    const file = path.join(store, 'manifest.json'); fs.writeFileSync(file, '{broken');
    assert.deepStrictEqual(manager.getQuarantinedFiles(), []); assert(manager.getStoreError());
    fs.writeFileSync(file, JSON.stringify({ version: '1.0', files: [] }));
    assert.deepStrictEqual(manager.getQuarantinedFiles(), []); assert.strictEqual(manager.getStoreError(), undefined);
  }));

  test('a last-moment source replacement is captured instead of discarded', () => fixture(async ({ manager, source }) => {
    const rename = fs.renameSync;
    fs.renameSync = (from, to) => {
      if (from === source) fs.writeFileSync(source, 'last-moment new work');
      return rename(from, to);
    };
    let entry;
    try { entry = await manager.quarantine(source, []); } finally { fs.renameSync = rename; }
    assert(entry); assert(!fs.existsSync(source));
    assert.strictEqual(fs.readFileSync(entry.quarantinePath, 'utf8'), 'last-moment new work');
    assert(await manager.restore(entry.id)); assert.strictEqual(fs.readFileSync(source, 'utf8'), 'last-moment new work');
  }));
  test('cross-device source capture fails closed with both copies retained', () => fixture(async ({ manager, source }) => {
    const rename = fs.renameSync;
    fs.renameSync = (from, to) => {
      if (from === source) throw Object.assign(new Error('Synthetic cross-device rename'), { code: 'EXDEV' });
      return rename(from, to);
    };
    try { assert.strictEqual(await manager.quarantine(source, []), null); } finally { fs.renameSync = rename; }
    assert.strictEqual(fs.readFileSync(source, 'utf8'), 'benign fixture');
    const [entry] = manager.getQuarantinedFiles(); assert(entry);
    assert.strictEqual(fs.readFileSync(entry.quarantinePath, 'utf8'), 'benign fixture');
  }));
  test('asynchronous observer rejection is isolated from committed transactions', () => fixture(async ({ source, store }) => {
    const messages = [];
    const manager = new QuarantineManager({ appendLine(message) { messages.push(message); } }, store);
    manager.addChangeHandler(async () => { throw new Error('Synthetic asynchronous observer failure'); });
    assert(await manager.quarantine(source, []));
    await new Promise(resolve => setImmediate(resolve));
    assert(messages.some(message => message.includes('Refresh failed'))); assert(!fs.existsSync(source));
  }));

  test('interrupted metadata refresh retains changed captured bytes for manual recovery', () => fixture(async ({ manager, source, store }) => {
    const rename = fs.renameSync; let commits = 0;
    fs.renameSync = (from, to) => {
      if (from === source) fs.writeFileSync(source, 'latest work');
      if (to === path.join(store, 'manifest.json') && ++commits === 2) throw new Error('Synthetic interrupted final commit');
      return rename(from, to);
    };
    try { assert.strictEqual(await manager.quarantine(source, []), null); } finally { fs.renameSync = rename; }
    const restarted = new QuarantineManager(output, store); const [entry] = restarted.getQuarantinedFiles();
    assert(entry); assert(!fs.existsSync(source));
    assert.strictEqual(fs.readFileSync(entry.quarantinePath, 'utf8'), 'latest work');
    assert.strictEqual(await restarted.restore(entry.id), false);
    assert.strictEqual(fs.readFileSync(entry.quarantinePath, 'utf8'), 'latest work'); assert.strictEqual(restarted.getCount(), 1);
  }));
  test('last-moment symlink capture never follows or changes its target', function () {
    if (process.platform === 'win32') this.skip();
    return fixture(async ({ manager, source, root, store }) => {
      const target = path.join(root, 'untouched.txt'); fs.writeFileSync(target, 'unrelated fixture');
      const rename = fs.renameSync;
      fs.renameSync = (from, to) => {
        if (from === source) { fs.unlinkSync(source); fs.symlinkSync(target, source); }
        return rename(from, to);
      };
      try { assert.strictEqual(await manager.quarantine(source, []), null); } finally { fs.renameSync = rename; }
      assert.strictEqual(fs.readFileSync(target, 'utf8'), 'unrelated fixture');
      const manifest = JSON.parse(fs.readFileSync(path.join(store, 'manifest.json')));
      assert.strictEqual(manifest.files.length, 1); assert(fs.lstatSync(manifest.files[0].quarantinePath).isSymbolicLink());
      assert.strictEqual(await manager.restore(manifest.files[0].id), false);
      assert.strictEqual(fs.readFileSync(target, 'utf8'), 'unrelated fixture');
    });
  });

  test('hard-linked sources are refused without changing aliases or their permissions', () => fixture(async ({ manager, source, root }) => {
    const alias = path.join(root, 'alias.txt'); fs.linkSync(source, alias);
    const mode = fs.statSync(alias).mode;
    assert.strictEqual(await manager.quarantine(source, []), null);
    assert.strictEqual(fs.readFileSync(source, 'utf8'), 'benign fixture');
    assert.strictEqual(fs.readFileSync(alias, 'utf8'), 'benign fixture');
    assert.strictEqual(fs.statSync(alias).mode, mode); assert.strictEqual(manager.getCount(), 0);
  }));

});

suite('Staged restore regressions', () => {
  async function fixture(run) {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'fig-staged-'));
    const store = path.join(root, 'store'), source = path.join(root, 'benign.txt');
    fs.writeFileSync(source, 'complete original bytes');
    const manager = new QuarantineManager({appendLine() {}}, store);
    const entry = await manager.quarantine(source, []);
    assert(entry);
    try { await run({root, store, source, manager, entry}); }
    finally { fs.rmSync(root, {recursive:true,force:true}); }
  }
  test('partial write fails before a destination is published and restart can retry', () => fixture(async ({store, source, manager, entry}) => {
    const write = fs.writeFileSync;
    fs.writeFileSync = (fd, ...args) => { if (typeof fd === 'number') { write(fd, 'partial'); throw new Error('Synthetic disk full'); } return write(fd, ...args); };
    try { assert.strictEqual(await manager.restore(entry.id), false); } finally { fs.writeFileSync = write; }
    assert(!fs.existsSync(source)); assert(fs.existsSync(entry.quarantinePath));
    const restarted = new QuarantineManager({appendLine() {}}, store);
    assert(await restarted.restore(entry.id)); assert.strictEqual(fs.readFileSync(source, 'utf8'), 'complete original bytes');
  }));
  test('writer after destination publication preserves its work and the recovery record', () => fixture(async ({source, manager, entry}) => {
    const link = fs.linkSync;
    fs.linkSync = (from, to) => { link(from, to); if (to === source) fs.writeFileSync(source, 'newer work'); };
    try { assert.strictEqual(await manager.restore(entry.id), false); } finally { fs.linkSync = link; }
    assert.strictEqual(fs.readFileSync(source, 'utf8'), 'newer work');
    assert.strictEqual(fs.readFileSync(entry.quarantinePath, 'utf8'), 'complete original bytes'); assert.strictEqual(manager.getCount(), 1);
  }));
  test('writer during final metadata commit retains payload and restores the record', () => fixture(async ({store, source, manager, entry}) => {
    const rename = fs.renameSync; let committed = false;
    fs.renameSync = (from, to) => { rename(from, to); if (!committed && to === path.join(store, 'manifest.json')) { committed = true; fs.writeFileSync(source, 'new work after commit'); } };
    try { assert.strictEqual(await manager.restore(entry.id), false); } finally { fs.renameSync = rename; }
    assert.strictEqual(fs.readFileSync(source, 'utf8'), 'new work after commit');
    assert.strictEqual(fs.readFileSync(entry.quarantinePath, 'utf8'), 'complete original bytes');
    assert.strictEqual(new QuarantineManager({appendLine() {}}, store).getCount(), 1);
  }));
  test('atomic publication refuses a last-moment conflicting destination', () => fixture(async ({source, manager, entry}) => {
    const link = fs.linkSync;
    fs.linkSync = (from, to) => { if (to === source) fs.writeFileSync(source, 'another writer'); return link(from, to); };
    try { assert.strictEqual(await manager.restore(entry.id), false); } finally { fs.linkSync = link; }
    assert.strictEqual(fs.readFileSync(source, 'utf8'), 'another writer'); assert(fs.existsSync(entry.quarantinePath)); assert.strictEqual(manager.getCount(), 1);
  }));
});

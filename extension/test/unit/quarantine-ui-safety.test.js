const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const Module = require('module');
const { QuarantineManager } = require('../../out/quarantine/quarantine-manager');

suite('Quarantine host UI safety', () => {
  async function fixture(run) {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'fig-quarantine-ui-'));
    const store = path.join(root, 'store');
    const manager = new QuarantineManager({ appendLine() {} }, store);
    const source = path.join(root, 'benign.txt');
    fs.writeFileSync(source, 'inert fixture');
    const entry = await manager.quarantine(source, []);
    const warnings = [], errors = [], information = [];
    const state = { choice: undefined, onConfirm: undefined, disposed: false, refreshes: 0 };
    let onMessage, onDispose;
    function subscription(handler, collection) {
      const disposable = { dispose() {} };
      if (collection) collection.push(disposable);
      return disposable;
    }
    const panel = {
      webview: { html: '', onDidReceiveMessage(handler, _context, collection) {
        onMessage = handler; return subscription(handler, collection);
      } },
      onDidDispose(handler, _context, collection) { onDispose = handler; return subscription(handler, collection); },
      reveal() {}, dispose() { if (!state.disposed) { state.disposed = true; onDispose(); } },
    };
    const vscode = {
      workspace: { isTrusted: true, textDocuments: [] },
      window: {
        createWebviewPanel() { return panel; },
        async showWarningMessage(message, options, ...items) {
          warnings.push({ message, options, items });
          if (state.onConfirm) await state.onConfirm();
          return state.choice;
        },
        async showErrorMessage(message) { errors.push(message); },
        async showInformationMessage(message) { information.push(message); },
      },
      ViewColumn: { Two: 2 }, TreeItemCollapsibleState: { None: 0 },
      TreeItem: class { constructor(label) { this.label = label; } },
      ThemeIcon: class {}, ThemeColor: class {},
      EventEmitter: class { event() {} fire() { state.refreshes++; } dispose() {} },
    };
    const file = require.resolve('../../out/quarantine/quarantine-provider');
    const previous = require.cache[file];
    delete require.cache[file];
    const load = Module._load;
    Module._load = function (name, ...args) { return name === 'vscode' ? vscode : load.call(this, name, ...args); };
    let providers;
    try { providers = require(file); } finally { Module._load = load; }
    const tree = new providers.QuarantineTreeProvider(manager);
    const view = providers.QuarantinePanel.createOrShow({}, manager);
    try {
      await run({ root, store, source, manager, entry, warnings, errors, information, state, vscode, panel, tree, view,
        send: message => onMessage(message) });
    } finally {
      view.dispose(); tree.dispose();
      delete require.cache[file];
      if (previous) require.cache[file] = previous;
      fs.rmSync(root, { recursive: true, force: true });
    }
  }

  for (const command of ['restore', 'delete', 'clearAll']) {
    test(`${command} dismissal leaves all files untouched`, () => fixture(async ({ send, manager, entry, source, warnings }) => {
      await send({ command, id: entry.id });
      assert.strictEqual(warnings.length, 1);
      assert.strictEqual(warnings[0].options.modal, true);
      assert(warnings[0].options.detail.includes(source));
      assert.strictEqual(manager.getCount(), 1);
      assert(fs.existsSync(entry.quarantinePath)); assert(!fs.existsSync(source));
    }));
  }

  test('explicit native restore confirmation restores and refreshes both views', () => fixture(async ({ send, manager, entry, source, state, information, panel, tree }) => {
    state.choice = 'Restore file';
    await send({ command: 'restore', id: entry.id });
    assert.strictEqual(fs.readFileSync(source, 'utf8'), 'inert fixture');
    assert.strictEqual(manager.getCount(), 0); assert.strictEqual(information.length, 1);
    assert(state.refreshes > 0); assert(panel.webview.html.includes('No files in quarantine'));
    assert.strictEqual(tree.getChildren()[0].label, 'No quarantined files');
  }));

  test('direct webview delete messages still require native irreversible confirmation', () => fixture(async ({ send, manager, entry, state, warnings }) => {
    state.choice = 'Delete permanently';
    await send({ command: 'delete', id: entry.id });
    assert.strictEqual(warnings.length, 1); assert(warnings[0].options.detail.includes('cannot be undone'));
    assert.strictEqual(manager.getCount(), 0); assert(!fs.existsSync(entry.quarantinePath));
  }));

  test('bulk confirmation deletes only its original snapshot', () => fixture(async ({ root, send, manager, entry, state, warnings }) => {
    state.choice = 'Delete selected files';
    let later;
    state.onConfirm = async () => {
      const source = path.join(root, 'later.txt'); fs.writeFileSync(source, 'later fixture');
      later = await manager.quarantine(source, []);
    };
    await send({ command: 'clearAll' });
    assert.strictEqual(manager.getCount(), 1); assert.strictEqual(manager.getQuarantinedFiles()[0].id, later.id);
    assert(!fs.existsSync(entry.quarantinePath)); assert(fs.existsSync(later.quarantinePath));
    assert(!warnings[0].options.detail.includes('later.txt'));
  }));

  test('restricted workspace blocks all panel mutations before confirmation', () => fixture(async ({ send, manager, entry, vscode, errors, warnings }) => {
    vscode.workspace.isTrusted = false;
    for (const command of ['restore', 'delete', 'clearAll']) await send({ command, id: entry.id });
    assert.strictEqual(manager.getCount(), 1); assert.strictEqual(errors.length, 3); assert.strictEqual(warnings.length, 0);
  }));

  test('trust is rechecked after confirmation', () => fixture(async ({ send, manager, entry, state, vscode }) => {
    state.choice = 'Delete permanently'; state.onConfirm = () => { vscode.workspace.isTrusted = false; };
    await send({ command: 'delete', id: entry.id }); assert.strictEqual(manager.getCount(), 1);
  }));

  test('dirty and existing restore destinations are protected', () => fixture(async ({ send, manager, entry, source, vscode, errors, warnings }) => {
    vscode.workspace.textDocuments = [{ uri: { scheme: 'file', fsPath: source }, isDirty: true }];
    await send({ command: 'restore', id: entry.id });
    vscode.workspace.textDocuments = []; fs.writeFileSync(source, 'new work');
    await send({ command: 'restore', id: entry.id });
    assert.strictEqual(manager.getCount(), 1); assert.strictEqual(warnings.length, 0);
    assert.strictEqual(errors.length, 2); assert.strictEqual(fs.readFileSync(source, 'utf8'), 'new work');
  }));

  test('dirty state acquired during confirmation blocks restore', () => fixture(async ({ send, manager, entry, source, state, vscode }) => {
    state.choice = 'Restore file';
    state.onConfirm = () => { vscode.workspace.textDocuments = [{ uri: { scheme: 'file', fsPath: source }, isDirty: true }]; };
    await send({ command: 'restore', id: entry.id }); assert.strictEqual(manager.getCount(), 1); assert(!fs.existsSync(source));
  }));

  test('entry changes during confirmation require a fresh review', () => fixture(async ({ send, manager, entry, store, state, errors }) => {
    state.choice = 'Delete permanently';
    state.onConfirm = () => {
      const file = path.join(store, 'manifest.json'); const manifest = JSON.parse(fs.readFileSync(file));
      manifest.files[0].detectedAt = new Date(0).toISOString(); fs.writeFileSync(file, JSON.stringify(manifest));
    };
    await send({ command: 'delete', id: entry.id });
    assert.strictEqual(manager.getCount(), 1); assert(errors.some(error => error.includes('selection changed')));
  }));

  test('corrupt store is visibly unavailable instead of empty', () => fixture(async ({ store, view, tree, panel, send, errors, warnings }) => {
    fs.writeFileSync(path.join(store, 'manifest.json'), '{broken');
    view.update();
    assert(panel.webview.html.includes('Quarantine unavailable'));
    assert(!panel.webview.html.includes('No files in quarantine'));
    assert.strictEqual(tree.getChildren()[0].label, 'Quarantine unavailable');
    await send({ command: 'clearAll' }); assert.strictEqual(errors.length, 1); assert.strictEqual(warnings.length, 0);
  }));

  test('manager failure produces an error without a success notification', () => fixture(async ({ send, manager, entry, state, errors, information }) => {
    state.choice = 'Restore file'; manager.restore = async () => false;
    await send({ command: 'restore', id: entry.id });
    assert.strictEqual(errors.length, 1); assert.strictEqual(information.length, 0); assert.strictEqual(manager.getCount(), 1);
  }));

  test('repeat clicks do not start concurrent confirmations and closing cancels pending intent', () => fixture(async ({ send, manager, entry, state, view, warnings }) => {
    let release, opened;
    const confirmationOpened = new Promise(resolve => { opened = resolve; });
    state.choice = 'Delete permanently';
    state.onConfirm = () => { opened(); return new Promise(resolve => { release = resolve; }); };
    const first = send({ command: 'delete', id: entry.id }); await confirmationOpened;
    await send({ command: 'clearAll' }); assert.strictEqual(warnings.length, 1);
    view.dispose(); release(); await first;
    assert.strictEqual(manager.getCount(), 1);
  }));

  test('malformed webview messages are ignored without confirmation', () => fixture(async ({ send, manager, warnings }) => {
    for (const message of [null, 'delete', {}, { command: 'delete', id: {} }, { command: 'unrecognized' }]) await send(message);
    assert.strictEqual(manager.getCount(), 1); assert.strictEqual(warnings.length, 0);
  }));
});

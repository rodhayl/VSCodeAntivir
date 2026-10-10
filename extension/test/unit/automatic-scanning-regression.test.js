// Synthetic text only. Disposable in-process editor event stubs, no native acceptance claim.
const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { createHost, tick } = require('../helpers/extension-host-stub');
async function fixture(run, options = {}) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(),'fig-lifecycle-')), h = createHost(root,options), calls = [];
  const {Scanner} = h.load('scanner/scanner'), scan = Scanner.prototype.scanFile;
  Scanner.prototype.scanFile = function(...args) { calls.push(args[0]);return scan.apply(this,args); };
  try {h.activate();await tick();await run(h,root,calls);} finally {h.load('extension').deactivate();h.context.subscriptions.forEach(d=>d.dispose());fs.rmSync(root,{recursive:true,force:true});}
}
const fireConfig = h => h.fire('config',{affectsConfiguration:key=>key==='fig'||['fig.scanOnSave','fig.scanOnOpen','fig.realTimeWatching'].includes(key)});
suite('R6 live automatic scan settings', () => {
  test('off/on repeated updates dispose old work and keep one listener per route', () => fixture(async(h,root,calls) => {
    const file = path.join(root,'fixture.js');fs.writeFileSync(file,'// inert fixture');const doc=h.makeDocument(file,'// inert fixture');
    for (let cycle=0;cycle<3;cycle++) {
      assert.strictEqual(h.listenerCount('save'),1);assert.strictEqual(h.listenerCount('open'),1);assert.strictEqual(h.activeWatchers().length,1);
      const old = h.activeWatchers()[0];for (const key of ['scanOnSave','scanOnOpen','realTimeWatching'])h.user['fig.'+key]=false;fireConfig(h);
      assert.strictEqual(h.listenerCount('save'),0);assert.strictEqual(h.listenerCount('open'),0);assert.strictEqual(h.activeWatchers().length,0);
      const before=calls.length;h.fire('save',doc);h.fire('open',doc);old.change(h.uri(file));old.create(h.uri(file));assert.strictEqual(calls.length,before);
      for (const key of ['scanOnSave','scanOnOpen','realTimeWatching'])h.user['fig.'+key]=true;fireConfig(h);fireConfig(h);
      h.fire('save',doc);h.fire('open',doc);h.activeWatchers()[0].change(h.uri(file));h.activeWatchers()[0].create(h.uri(file));assert.strictEqual(calls.length,before+4);
    }
  }));
  test('initially disabled routes can be enabled independently and deactivate disposes them', () => fixture(async(h,root,calls) => {
    const file=path.join(root,'fixture.js');fs.writeFileSync(file,'// inert fixture');const doc=h.makeDocument(file,'// inert fixture');
    assert.strictEqual(h.listenerCount('save'),0);assert.strictEqual(h.listenerCount('open'),0);assert.strictEqual(h.activeWatchers().length,0);
    h.user['fig.scanOnSave']=true;fireConfig(h);h.fire('save',doc);h.fire('open',doc);assert.strictEqual(calls.length,1);
    h.user['fig.scanOnOpen']=true;fireConfig(h);h.fire('open',doc);assert.strictEqual(calls.length,2);
    h.user['fig.realTimeWatching']=true;fireConfig(h);h.activeWatchers()[0].change(h.uri(file));assert.strictEqual(calls.length,3);
    h.load('extension').deactivate();assert.strictEqual(h.listenerCount('save'),0);assert.strictEqual(h.listenerCount('open'),0);assert.strictEqual(h.activeWatchers().length,0);
  },{user:{'fig.scanOnSave':false,'fig.scanOnOpen':false,'fig.realTimeWatching':false}}));
  test('Restricted Mode remains manual even after settings and trust toggles', () => fixture(async(h,root,calls) => {
    const file=path.join(root,'fixture.js');fs.writeFileSync(file,'// inert fixture');const doc=h.makeDocument(file,'// inert fixture');
    for (const trusted of [false,true,false,true]) {
      h.vscode.workspace.isTrusted=trusted;fireConfig(h);h.fire('save',doc);h.fire('open',doc);
      assert.strictEqual(h.listenerCount('save'),0);assert.strictEqual(h.listenerCount('open'),0);assert.strictEqual(h.watchers.length,0);assert.strictEqual(calls.length,0);
    }
  },{trusted:false}));
  test('startup documents respect scanOnOpen disabled', async () => {
    const root=fs.mkdtempSync(path.join(os.tmpdir(),'fig-startup-'));
    const h=createHost(root,{user:{'fig.scanOnOpen':false,'fig.scanOnSave':false,'fig.realTimeWatching':false}});
    try {
      const file=path.join(root,'fixture.js');fs.writeFileSync(file,'// inert Invoke-Expression text');h.makeDocument(file,'// inert Invoke-Expression text');
      h.activate();await tick();assert.strictEqual(h.diagnostics.size,0);
      await h.commands.get('fig.scanFile')(h.uri(file));assert(h.diagnostics.get(file)?.length>0);
    } finally {h.load('extension').deactivate();h.context.subscriptions.forEach(d=>d.dispose());fs.rmSync(root,{recursive:true,force:true});}
  });
  test('stub registration disposals are idempotent and suppress old callbacks', () => fixture(async(h,root,calls) => {
    let count=0;const disposable=h.vscode.workspace.onDidSaveTextDocument(()=>count++);disposable.dispose();disposable.dispose();
    h.fire('save',{uri:{scheme:'untitled'}});assert.strictEqual(count,0);assert.strictEqual(calls.length,0);
    const watcher=h.vscode.workspace.createFileSystemWatcher('*');watcher.onDidChange(()=>count++);watcher.dispose();watcher.change(h.uri(root));assert.strictEqual(count,0);
  }));
});

const assert = require('assert');
const fs = require('fs');
const path = require('path');
const os = require('os');
const { createHost, modelResponse, tick } = require('../helpers/extension-host-stub');
const flagged = '// inert text fixture: eval(\n';
const clean = 'const greeting = "hello";\n';
async function fixture(run, options={}) {
  const root=fs.mkdtempSync(path.join(os.tmpdir(),'fig-host-'));
  const write=(name,text)=>{const file=path.join(root,name);fs.mkdirSync(path.dirname(file),{recursive:true});fs.writeFileSync(file,text);return file;};
  const host=createHost(root,options);
  try { await run(host,root,write); } finally { host.load('extension').deactivate(); fs.rmSync(root,{recursive:true,force:true}); }
}
const llmUser={'fig.llm.enabled':true,'fig.llm.provider':'custom','fig.llm.baseUrl':'https://fixture.invalid/v1'};
suite('Extension scan and consent safety',()=>{
  test('dismissed startup review leaves benign tasks/npm/git unchanged',()=>fixture(async(h,root,write)=>{
    const values={'.vscode/tasks.json':'{"tasks":[{"command":"echo hello","runOptions":{"runOn":"folderOpen"}}]}','package.json':'{"scripts":{"prepare":"node benign-build.js"}}','.npmrc':'ignore-scripts=false\n','.git/config':'[core]\nfsmonitor = true\n'};
    for(const [name,text] of Object.entries(values))write(name,text);
    h.vscode.workspace.workspaceFolders=[{name:'fixture',uri:h.uri(root)}]; h.activate(); await tick();await tick();
    for(const [name,text] of Object.entries(values))assert.strictEqual(fs.readFileSync(path.join(root,name),'utf8'),text);
    assert(!fs.existsSync(path.join(root,'.vscode/tasks.json.fig-backup')));
    assert(h.messages.filter(m=>m.type==='warning').length>=3);
  }));
  test('multi-root scan keeps earlier findings when final root is clean',()=>fixture(async(h,root,write)=>{
    const first=write('a/package.json','{"scripts":{"postinstall":"node benign-build.js"}}');write('b/clean.js',clean);
    h.activate();await tick();h.vscode.workspace.workspaceFolders=['a','b'].map(name=>({name,uri:h.uri(path.join(root,name))}));
    await h.commands.get('fig.scanWorkspace')();assert(h.diagnostics.get(first)?.length>0);
    assert(!h.messages.some(m=>m.text.includes('Workspace is clean')));
  }));
  test('unopened explorer file is scanned and missing file is a visible failure',()=>fixture(async(h,_root,write)=>{
    const file=write('package.json','{"scripts":{"postinstall":"node benign-build.js"}}');h.activate();await tick();
    assert.strictEqual(h.vscode.workspace.textDocuments.length,0);await h.commands.get('fig.scanFile')(h.uri(file));assert(h.diagnostics.get(file)?.length>0);
    await h.commands.get('fig.scanFile')(h.uri(file+'.missing'));assert(h.messages.at(-1).text.includes('failed'));
  }));
  test('excluded and oversize document/file watcher results are cleared',()=>fixture(async(h,_root,write)=>{
    const file=write('example.js',flagged);h.activate();await tick();const doc=h.makeDocument(file,flagged);h.fire('save',doc);assert(h.diagnostics.get(file)?.length>0);
    h.user['fig.excludedPaths']=['**/example.js'];h.fire('config',{affectsConfiguration:key=>key==='fig'});h.fire('save',doc);assert(!h.diagnostics.has(file));
    h.user['fig.excludedPaths']=[];h.user['fig.maxFileSizeKB']=1;h.fire('config',{affectsConfiguration:key=>key==='fig'});h.fire('save',doc);assert(h.diagnostics.get(file)?.length>0);
    fs.writeFileSync(file,flagged+' '.repeat(2048));h.watchers[0].change(h.uri(file));assert(!h.diagnostics.has(file));
  }));
  test('minimum severity is applied to actual diagnostics and deleted files clear',()=>fixture(async(h,_root,write)=>{
    const file=write('package.json','{"scripts":{"postinstall":"node benign-build.js"}}');h.activate();await tick();await h.commands.get('fig.scanFile')(h.uri(file));
    assert.strictEqual((h.diagnostics.get(file)||[]).length,0);
    h.user['fig.minimumSeverity']='info';h.fire('config',{affectsConfiguration:key=>key==='fig'});assert(h.diagnostics.get(file)?.length>0);
    h.watchers[0].delete(h.uri(file));assert(!h.diagnostics.has(file));
  },{user:{'fig.minimumSeverity':'critical'}}));
  test('workspace LLM overrides cannot enable a client or auto transmission',()=>fixture(async(h,_root,write)=>{
    const file=write('example.js',flagged);h.makeDocument(file,flagged);h.activate();await tick();
    assert.strictEqual(h.clients.length,0);assert.strictEqual(h.modelCalls.length,0);
  },{workspace:{...llmUser,'fig.llm.autoAnalyze':true}}));
  test('declined outbound consent makes zero model requests',()=>fixture(async(h,_root,write)=>{
    const file=write('example.js',clean);h.activate();await tick();await h.vscode.window.showTextDocument(h.makeDocument(file,clean));
    await h.commands.get('fig.llmAnalyze')();assert.strictEqual(h.modelCalls.length,0);
    const consent=h.messages.find(m=>m.text.includes('Send analysis input'));assert(consent.options.detail.includes('https://fixture.invalid/v1'));
  },{user:llmUser}));
  test('Cancel aborts SDK transport and disposes its listener',()=>fixture(async(h,_root,write)=>{
    const file=write('example.js',clean);h.activate();await tick();await h.vscode.window.showTextDocument(h.makeDocument(file,clean));h.replies.push('Analyze once');
    const pending=h.commands.get('fig.llmAnalyze')();await tick();assert.strictEqual(h.modelCalls.length,1);h.cancel();await pending;
    assert(h.modelCalls[0].options.signal.aborted);assert.strictEqual(h.subscriptions(),0);assert(h.messages.some(m=>m.text==='LLM analysis cancelled'));
  },{user:llmUser}));
  test('edited clean document rejects stale result even if transport ignores abort',()=>fixture(async(h,_root,write)=>{
    const file=write('example.js',flagged);h.activate();await tick();const doc=h.makeDocument(file,flagged);await h.vscode.window.showTextDocument(doc);h.replies.push('Analyze once');
    const pending=h.commands.get('fig.llmAnalyze')();await tick();doc.text=clean;doc.version++;h.fire('change',{document:doc});h.fire('save',doc);
    h.modelCalls[0].resolve(modelResponse([{type:'old-fixture',severity:'high',line:1,evidence:'old text'}]));await pending;
    assert(!(h.diagnostics.get(file)||[]).some(d=>String(d.code).startsWith('llm-')));
  },{user:llmUser,ignoreAbort:true}));
  test('config change revokes automatic consent and prevents old result publication',()=>fixture(async(h,root,write)=>{
    const file=write('example.js',flagged);h.activate();await tick();h.vscode.workspace.workspaceFolders=[{name:'fixture',uri:h.uri(root)}];const doc=h.makeDocument(file,flagged);await h.vscode.window.showTextDocument(doc);
    h.replies.push('Allow automatic analysis this session');const pending=h.commands.get('fig.llmAnalyze')();await tick();
    h.user['fig.llm.enabled']=false;h.fire('config',{affectsConfiguration:key=>key==='fig'||key==='fig.llm'});
    h.modelCalls[0].resolve(modelResponse([{type:'old-config',severity:'high',line:1,evidence:'old'}]));await pending;
    h.fire('save',doc);await tick();assert.strictEqual(h.modelCalls.length,1);assert(!(h.diagnostics.get(file)||[]).some(d=>String(d.code).startsWith('llm-')));
  },{user:{...llmUser,'fig.llm.autoAnalyze':true},ignoreAbort:true}));
  test('automatic analysis requires session consent and never scans outside workspace',()=>fixture(async(h,root,write)=>{
    const inside=write('workspace/example.js',flagged), outside=write('outside.js',flagged);h.activate();await tick();
    h.vscode.workspace.workspaceFolders=[{name:'fixture',uri:h.uri(path.join(root,'workspace'))}];const doc=h.makeDocument(inside,flagged);h.fire('save',doc);await tick();assert.strictEqual(h.modelCalls.length,0);
    await h.vscode.window.showTextDocument(doc);h.replies.push('Allow automatic analysis this session');const first=h.commands.get('fig.llmAnalyze')();await tick();h.modelCalls[0].resolve(modelResponse());await first;await tick();
    h.fire('save',h.makeDocument(outside,flagged));await tick();assert.strictEqual(h.modelCalls.length,1);
  },{user:{...llmUser,'fig.llm.autoAnalyze':true}}));
  test('automatic analysis refuses an inside-workspace symlink to outside content', function () {
    if (process.platform === 'win32') this.skip();
    return fixture(async(h,root,write)=>{
      const inside=write('workspace/example.js',clean), outside=write('outside.js',flagged);
      const link=path.join(root,'workspace/link.js');fs.symlinkSync(outside,link);
      h.activate();await tick();h.vscode.workspace.workspaceFolders=[{name:'fixture',uri:h.uri(path.join(root,'workspace'))}];
      await h.vscode.window.showTextDocument(h.makeDocument(inside,clean));h.replies.push('Allow automatic analysis this session');
      const first=h.commands.get('fig.llmAnalyze')();await tick();h.modelCalls[0].resolve(modelResponse());await first;
      h.fire('save',h.makeDocument(link,flagged));await tick();assert.strictEqual(h.modelCalls.length,1);
    },{user:{...llmUser,'fig.llm.autoAnalyze':true}});
  });
  test('Restricted Mode suppresses outbound client even with user-enabled setting',()=>fixture(async(h,_root,write)=>{
    const file=write('example.js',flagged);h.makeDocument(file,flagged);h.activate();await tick();assert.strictEqual(h.clients.length,0);assert.strictEqual(h.modelCalls.length,0);
  },{user:llmUser,trusted:false}));
  for (const command of ['fig.llmSuggestRule', 'fig.llmExplain']) {
    test(`${command} aborts transport when disabled and disposes the listener`,()=>fixture(async(h,_root,write)=>{
      const file=write('example.js',clean);h.activate();await tick();await h.vscode.window.showTextDocument(h.makeDocument(file,clean));h.replies.push('Analyze once');
      const pending=h.commands.get(command)(file,'fixture-rule','benign description','benign evidence');await tick();
      assert.strictEqual(h.modelCalls.length,1);
      h.user['fig.llm.enabled']=false;h.fire('config',{affectsConfiguration:key=>key==='fig'||key==='fig.llm'});
      const signal=h.modelCalls[0].options?.signal;
      // Resolve even on the old implementation, so a missing abort does not leave an outstanding stub request.
      h.modelCalls[0].resolve(modelResponse());await pending;
      assert(signal?.aborted);assert.strictEqual(h.subscriptions(),0);
      assert(!h.messages.some(m=>m.text.includes('opened')||m.text.includes('written to Output')));
    },{user:{...llmUser}}));
    test(`${command} supports Cancel and discards a late response`,()=>fixture(async(h,_root,write)=>{
      const file=write('example.js',clean);h.activate();await tick();await h.vscode.window.showTextDocument(h.makeDocument(file,clean));h.replies.push('Analyze once');
      const pending=h.commands.get(command)(file,'fixture-rule','benign description','benign evidence');await tick();h.cancel();
      h.modelCalls[0].resolve(modelResponse());await pending;
      assert(h.modelCalls[0].options?.signal?.aborted);assert.strictEqual(h.subscriptions(),0);
      assert(!h.messages.some(m=>m.text.includes('opened')||m.text.includes('written to Output')));
    },{user:{...llmUser},ignoreAbort:true}));
  }
  for (const route of ['task', 'npm', 'threat']) {
    for (const stage of ['initial review', 'final confirmation']) {
    test(`${route} notification quarantine refuses bytes changed during ${stage}`,()=>fixture(async(h,root,write)=>{
      const file=write('benign.json','{"example":true}');
      const {BlockingNotificationService}=h.load('notifications/blocking-notification');
      const {QuarantineManager}=h.load('quarantine/quarantine-manager');
      const output={appendLine(){}};const service=new BlockingNotificationService(output);
      const manager=new QuarantineManager(output,path.join(root,'store'));service.setQuarantineManager(manager);
      const change=()=>{fs.writeFileSync(file,'new unrelated benign work');return 'Quarantine file';};
      h.replies.push(...(stage==='initial review'?[change,'Quarantine file']:['Quarantine file',change]));
      if(route==='task')await service.notifyTaskBlocked({hasThreats:true,tasksJsonPath:file,threats:[{taskLabel:'fixture',type:'auto-execute'}]});
      if(route==='npm')await service.notifyNpmScriptBlocked({hasThreats:true,packageJsonPath:file,threats:[{scriptName:'fixture',reason:'example'}]});
      if(route==='threat')await service.notifyThreatDetected(file,[{severity:0,ruleName:'fixture'}]);
      assert.strictEqual(fs.readFileSync(file,'utf8'),'new unrelated benign work');assert.strictEqual(manager.getCount(),0);
      assert(h.messages.some(m=>m.text.includes('changed during confirmation')));
      assert(!h.messages.some(m=>m.text==='FIG: File quarantined.'));
    }));
    }
  }
  for (const route of ['task', 'npm']) {
    test(`${route} quarantine refuses bytes changed after inspection before notification`,()=>fixture(async(h,root,write)=>{
      const original=route==='task'?'{"tasks":[{"command":"echo hello","runOptions":{"runOn":"folderOpen"}}]}':'{"scripts":{"prepare":"node benign-build.js"}}';
      const file=write(route==='task'?'tasks.json':'package.json',original);
      const output={appendLine(){}};
      const {BlockingNotificationService}=h.load('notifications/blocking-notification');
      const {QuarantineManager}=h.load('quarantine/quarantine-manager');
      const Interceptor=route==='task'?h.load('interceptors/task-interceptor').TaskInterceptor:h.load('interceptors/npm-script-interceptor').NpmScriptInterceptor;
      const review=await new Interceptor(output).scanAndBlock(file);assert(review.hasThreats);
      const service=new BlockingNotificationService(output);const manager=new QuarantineManager(output,path.join(root,'store'));service.setQuarantineManager(manager);
      fs.writeFileSync(file,'new unrelated benign work');h.replies.push('Quarantine file','Quarantine file');
      if(route==='task')await service.notifyTaskBlocked(review);else await service.notifyNpmScriptBlocked(review);
      assert.strictEqual(fs.readFileSync(file,'utf8'),'new unrelated benign work');assert.strictEqual(manager.getCount(),0);
      assert(!h.messages.some(m=>m.text==='Move this file to quarantine?'));
    }));
  }
  test('notification quarantine still accepts unchanged explicitly approved bytes',()=>fixture(async(h,root,write)=>{
    const file=write('benign.json','{"example":true}');
    const {BlockingNotificationService}=h.load('notifications/blocking-notification');
    const {QuarantineManager}=h.load('quarantine/quarantine-manager');
    const output={appendLine(){}};const service=new BlockingNotificationService(output);
    const manager=new QuarantineManager(output,path.join(root,'store'));service.setQuarantineManager(manager);
    h.replies.push('Quarantine file','Quarantine file');await service.notifyThreatDetected(file,[{severity:0,ruleName:'fixture'}]);
    assert(!fs.existsSync(file));assert.strictEqual(manager.getCount(),1);
    assert.strictEqual(fs.readFileSync(manager.getQuarantinedFiles()[0].quarantinePath,'utf8'),'{"example":true}');
  }));
});

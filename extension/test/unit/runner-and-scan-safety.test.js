const assert = require('assert');
const fs = require('fs');
const path = require('path');
const os = require('os');
const vm = require('vm');
const { Scanner } = require('../../out/scanner/scanner');
suite('Runner and incomplete-scan safety', () => {
  for (const failures of [0,1]) test(`unit CLI invokes tests and propagates ${failures} failure(s)`, async () => {
    const module = {exports:{}}; const processStub={}; let runs=0,added=0;
    class Mocha {addFile(){added++;}run(done){runs++;done(failures);}}
    const requireStub=name=>name==='mocha'?Mocha:name==='fs'?{readdirSync:()=>[{name:'fixture.test.js',isDirectory:()=>false}]}:require(name);
    requireStub.main=module;
    vm.runInNewContext(fs.readFileSync(path.join(__dirname,'../runUnit.js'),'utf8'),{module,exports:module.exports,require:requireStub,__dirname:'/synthetic/test',process:processStub,console:{error(){}}});
    await new Promise(resolve=>setImmediate(resolve));
    assert.strictEqual(runs,1);assert.strictEqual(added,1);assert.strictEqual(processStub.exitCode,failures?1:undefined);
  });
  test('unreadable file is an explicit error, never a scanned clean result', () => {
    const result=new Scanner().scanFile(path.join(os.tmpdir(),'fig-nonexistent-'+Date.now()+'.js'));
    assert.strictEqual(result.status,'error');assert(result.detail);
  });
  test('unreadable root records incomplete enumeration', () => {
    const summary=new Scanner().scanWorkspace(path.join(os.tmpdir(),'fig-nonexistent-'+Date.now()));
    assert.strictEqual(summary.scannedFiles,0);assert(summary.errors.length>0);
  });
  test('malformed task and package configurations are explicit parse errors', () => {
    const scanner=new Scanner();
    for(const file of ['tasks.json','package.json'])assert.strictEqual(scanner.scanFile(file,'{bad').status,'error');
  });
  test('valid JSONC tasks remain inspected', () => {
    const result=new Scanner().scanFile('tasks.json','// harmless comment\n{"tasks":[{"command":"echo hello","runOptions":{"runOn":"folderOpen"}},],}');
    assert.strictEqual(result.status,'scanned');assert(result.threats.some(t=>t.ruleId==='vscode-task-autoexec'));
  });
});

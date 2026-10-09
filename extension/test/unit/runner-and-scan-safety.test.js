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
  for (const runner of ['../runUnit.js','../suite/index.js']) {
    for (const namespace of [false,true]) test(`${runner} accepts ${namespace ? 'ESM namespace' : 'CommonJS constructor'}`, async () => {
      const module = {exports:{}}; let runs=0,added=0;
      class Mocha {addFile(){added++;}run(done){runs++;done(0);}}
      const requireStub=name=>name==='mocha'?(namespace?{default:Mocha}:Mocha):name==='fs'?{readdirSync:()=>[{name:'fixture.test.js',isDirectory:()=>false}]}:require(name);
      vm.runInNewContext(fs.readFileSync(path.join(__dirname,runner),'utf8'),{module,exports:module.exports,require:requireStub,__dirname:'/synthetic/test'});
      const run=typeof module.exports==='function'?module.exports:module.exports.run;
      await run();
      assert.strictEqual(runs,1);assert.strictEqual(added,1);
    });
  }
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

const {RuleLoader} = require('../../out/rules/rule-loader');
suite('Rule-loading capability contracts', () => {
  for(const matcher of [{id:'a',type:'file-structure',requiredFiles:['package.json']},{id:'a',type:'regex',pattern:'['},{id:'a',type:'string-any',patterns:[42]},{id:'a',type:'ast',pattern:42}]) test(`unsupported or malformed matcher ${JSON.stringify(matcher)} is visible`, () => {
    const root=fs.mkdtempSync(path.join(os.tmpdir(),'fig-rule-contract-'));
    try {
      fs.writeFileSync(path.join(root,'rule.json'),JSON.stringify({id:'test',name:'Test',severity:'low',matchers:[matcher],condition:{type:'any',of:['a']},appliesTo:{filePatterns:['**/*']}}));
      const loader=new RuleLoader();loader.loadFromDirectory(root);assert.strictEqual(loader.getRules().length,0);assert(loader.getErrors().length>0);
    } finally {fs.rmSync(root,{recursive:true,force:true});}
  });
});

suite('Task configuration shape validation', () => {
  for(const value of [null,[],true,42,{tasks:null},{tasks:[null]},{tasks:[42]},{tasks:[[]]}]) test(`invalid task structure ${JSON.stringify(value)} is incomplete`, () => {
    const result=new Scanner().scanFile('tasks.json',JSON.stringify(value));assert.strictEqual(result.status,'error');assert(result.detail);
  });
});

const assert = require('assert');
const fs = require('fs');
const path = require('path');
const vm = require('vm');
suite('Development Host evidence scope', () => {
  test('runner opens an isolated workspace with automatic tasks off, never samples', async () => {
    let options;const processStub={};
    const request = name => name==='@vscode/test-electron'?{runTests:async value=>{
      options=value;assert(!options.launchArgs[0].includes('samples'));
      const settings=JSON.parse(fs.readFileSync(path.join(options.launchArgs[0],'.vscode/settings.json'),'utf8'));
      assert.strictEqual(settings['task.allowAutomaticTasks'],'off');
    }}:require(name);
    vm.runInNewContext(fs.readFileSync(path.resolve(__dirname,'../runTest.js'),'utf8'),{require:request,__dirname:path.resolve(__dirname,'..'),process:processStub,console});
    await new Promise(resolve=>setImmediate(resolve));
    assert(options);assert.strictEqual(processStub.exitCode,undefined);
    assert(!fs.existsSync(options.launchArgs[0]));assert(!options.launchArgs.some(arg=>arg.includes('--no-sandbox')));
  });
  test('host checks cannot overwrite historical screenshots or use unconditional passes', () => {
    const file=path.resolve(__dirname,'../suite/development-host.test.js');
    const source=fs.readFileSync(file,'utf8');
    assert(!fs.existsSync(path.resolve(__dirname,'../suite/native-acceptance.test.js')));
    assert(!source.includes('assert.ok(true'));assert(!source.includes('captureScreenshot'));assert(!source.includes('native-portfolio-'));
    assert(source.includes('Development Host'));assert(source.includes('vscode.TabInputWebview'));
  });
});

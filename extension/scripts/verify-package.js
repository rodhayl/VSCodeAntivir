// Validate the exact built artifact without launching VS Code or invoking sample/provider code.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');
const {spawnSync} = require('node:child_process');
const yauzl = require('yauzl');
const hash = bytes => crypto.createHash('sha256').update(bytes).digest('hex');

async function verify(artifact) {
  const temporary = fs.mkdtempSync(path.join(os.tmpdir(), 'fig-vsix-'));
  try {
    const files = [];
    await new Promise((resolve,reject)=>yauzl.open(artifact,{lazyEntries:true},(error,zip)=>{
      if(error)return reject(error);
      zip.on('error',reject); zip.on('end',resolve);
      zip.on('entry',entry=>{
        const target=path.resolve(temporary,entry.fileName);
        const relative=path.relative(temporary,target);
        if(relative.startsWith('..'+path.sep)||path.isAbsolute(relative)||relative==='..')return reject(new Error('Unsafe package path'));
        if(entry.fileName.endsWith('/')){fs.mkdirSync(target,{recursive:true});zip.readEntry();return;}
        if(entry.uncompressedSize>20*1024*1024)return reject(new Error('Unexpected oversized package file'));
        zip.openReadStream(entry,(streamError,stream)=>{
          if(streamError)return reject(streamError);
          const chunks=[];
          stream.on('error',reject);stream.on('data',chunk=>chunks.push(chunk));
          stream.on('end',()=>{
            try {fs.mkdirSync(path.dirname(target),{recursive:true});fs.writeFileSync(target,Buffer.concat(chunks));files.push(entry.fileName);zip.readEntry();}
            catch(writeError){reject(writeError);}
          });
        });
      });
      zip.readEntry();
    }));
    const root=path.join(temporary,'extension');
    const pkg=JSON.parse(fs.readFileSync(path.join(root,'package.json'),'utf8'));
    const metadata=JSON.parse(fs.readFileSync(path.join(root,'out/build-metadata.json'),'utf8'));
    assert.equal(pkg.name,'fake-interview-guard');
    assert.equal(pkg.publisher,'fakeinterviewguard');
    assert.equal(pkg.capabilities.untrustedWorkspaces.supported,'limited');
    assert(files.includes('extension/readme.md'));
    assert(files.includes('extension/LICENSE.txt'));
    assert(files.includes('extension/icon.png'));
    assert.equal(files.filter(file=>file.startsWith('extension/rules/')&&file.endsWith('.json')).length,53);
    assert.equal(files.filter(file=>file.startsWith('extension/prompts/')&&file.endsWith('.prompt.md')).length,4);
    assert(!files.some(file=>file.includes('/.vscode-test/')||file.endsWith('.map')||file.endsWith('.vsix')));
    assert(!files.some(file=>/^extension\/(src|test|scripts)\//.test(file)));
    for(const dependency of Object.keys(pkg.dependencies))assert(fs.existsSync(path.join(root,'node_modules',dependency,'package.json')),`Missing runtime dependency ${dependency}`);
    const probe = spawnSync(process.execPath,['-e',`
      const assert=require('node:assert/strict');
      const path=require('node:path');
      const root=process.argv[1];
      const Module=require('node:module');
      const load=Module._load;
      Module._load=function(name,...args){
        if(name==='vscode')return {TreeItem:class{},CodeActionKind:{QuickFix:'quickfix'}};
        const resolved=Module._resolveFilename(name,...args);
        if(path.isAbsolute(resolved))assert(resolved.startsWith(root+path.sep),'Dependency escaped extracted artifact: '+resolved);
        return load.call(this,name,...args);
      };
      const extension=require(path.join(root,'out/extension.js'));
      assert.equal(typeof extension.activate,'function');assert.equal(typeof extension.deactivate,'function');
      const {Scanner}=require(path.join(root,'out/scanner/scanner.js'));
      const scanner=new Scanner();const loaded=scanner.loadRules(path.join(root,'rules'));
      assert.equal(loaded.count,53);assert.equal(loaded.errors.length,0);
      const result=scanner.scanFile('package.json','{"dependencies":{"event-stream":"3.3.6"}}');
      assert(result.threats.some(threat=>threat.ruleId==='npm-known-bad-package'));
      console.log('Packaged runtime imports, 53 rules and inert manifest scan passed');
    `,root],{cwd:temporary,encoding:'utf8',env:{...process.env,NODE_PATH:'',NODE_OPTIONS:''}});
    assert.equal(probe.status,0,probe.stderr || probe.stdout);
    return {artifact:path.basename(artifact),sha256:hash(fs.readFileSync(artifact)),bytes:fs.statSync(artifact).size,files:files.length,sourceTreeSha256:metadata.sourceTreeSha256,runtimeDependencies:Object.keys(pkg.dependencies),scope:'Isolated extracted-package import/scanner smoke. VS Code API is stubbed only at import; not installed Extension Host or GUI acceptance.',result:probe.stdout.trim()};
  } finally {fs.rmSync(temporary,{recursive:true,force:true});}
}
module.exports={verify};
if(require.main===module){const pkg=require('../package.json');verify(path.resolve(process.argv[2]||`${pkg.name}-${pkg.version}.vsix`)).then(result=>console.log(JSON.stringify(result,null,2))).catch(error=>{console.error(error);process.exitCode=1;});}

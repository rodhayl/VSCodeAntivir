const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const root = path.resolve(__dirname, '..');
const hash = bytes => crypto.createHash('sha256').update(bytes).digest('hex');
const files = [];
function walk(directory) {
  for(const entry of fs.readdirSync(directory,{withFileTypes:true}).sort((a,b)=>a.name.localeCompare(b.name))) {
    const full=path.join(directory,entry.name);
    if(entry.isDirectory())walk(full);
    else if(entry.isFile())files.push({path:path.relative(root,full).split(path.sep).join('/'),sha256:hash(fs.readFileSync(full))});
  }
}
for(const directory of ['src','rules','prompts'])walk(path.join(root,directory));
for(const name of ['package.json','package-lock.json','tsconfig.json','scripts/prepare-package.js'])files.push({path:name,sha256:hash(fs.readFileSync(path.join(root,name)))});
files.sort((a,b)=>a.path.localeCompare(b.path));
const metadata={schemaVersion:1,packageName:require('../package.json').name,packageVersion:require('../package.json').version,sourceTreeSha256:hash(JSON.stringify(files)),files};
fs.mkdirSync(path.join(root,'out'),{recursive:true});
fs.writeFileSync(path.join(root,'out','build-metadata.json'),JSON.stringify(metadata,null,2)+'\n');
for(const name of ['README.md','CHANGELOG.md','LICENSE'])fs.copyFileSync(path.join(root,'..',name),path.join(root,name));
console.log(`Package source-tree SHA-256: ${metadata.sourceTreeSha256}`);

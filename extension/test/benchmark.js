const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const crypto = require('node:crypto');
const {performance} = require('node:perf_hooks');
const {Scanner} = require('../out/scanner/scanner');
const root = path.resolve(__dirname, '..');
const corpusPath = path.join(__dirname, 'corpus', 'portfolio.json');
const hash = bytes => crypto.createHash('sha256').update(bytes).digest('hex');

function digestTree(directory) {
  const files = [];
  function walk(dir) {
    for (const entry of fs.readdirSync(dir, {withFileTypes:true}).sort((a,b)=>a.name.localeCompare(b.name))) {
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) walk(full);
      else if (entry.isFile()) files.push([path.relative(directory,full).split(path.sep).join('/'),hash(fs.readFileSync(full))]);
    }
  }
  walk(directory);
  return hash(JSON.stringify(files));
}

function benchmark(iterations = 20) {
  if (!Number.isSafeInteger(iterations) || iterations < 1 || iterations > 1000) throw new Error('iterations must be an integer from 1 to 1000');
  const corpusBytes = fs.readFileSync(corpusPath);
  const corpus = JSON.parse(corpusBytes);
  const scanner = new Scanner();
  const loaded = scanner.loadRules(path.join(root, 'rules'));
  if (loaded.errors.length) throw new Error(loaded.errors.join('\n'));
  const matrix = {truePositive:0,falsePositive:0,trueNegative:0,falseNegative:0,errors:0};
  const byRule = {};
  let contractFailures = 0;
  const results = corpus.cases.map(item => {
    const file = path.join(root, 'synthetic-corpus', item.id, item.file);
    const result = scanner.scanFile(file, item.content);
    const ids = [...new Set(result.threats.map(threat=>threat.ruleId))].sort();
    const positive = item.label === 'suspicious-pattern';
    if (result.status !== 'scanned') matrix.errors++;
    else matrix[positive ? (ids.length ? 'truePositive' : 'falseNegative') : (ids.length ? 'falsePositive' : 'trueNegative')]++;
    for(const id of ids) {
      byRule[id] ||= {positiveCaseHits:0,benignCaseHits:0};
      byRule[id][positive ? 'positiveCaseHits' : 'benignCaseHits']++;
    }
    const missing = (item.requiredRuleIds || []).filter(id=>!ids.includes(id));
    if (result.status !== 'scanned' || missing.length) contractFailures++;
    return {id:item.id,label:item.label,bytes:Buffer.byteLength(item.content),status:result.status,ruleIds:ids,missingRequiredRules:missing};
  });
  // Warm-up is excluded. Content is supplied directly; there is no file execution, provider or network call.
  for(const item of corpus.cases) scanner.scanFile(path.join(root,'synthetic-corpus',item.id,item.file),item.content);
  const timings = [], passes = [];
  for(let round=0;round<iterations;round++) {
    const passStart = performance.now();
    for(const item of corpus.cases) {
      const started = performance.now();
      scanner.scanFile(path.join(root,'synthetic-corpus',item.id,item.file),item.content);
      timings.push(performance.now()-started);
    }
    passes.push(performance.now()-passStart);
  }
  function distribution(values) {
    const sorted=[...values].sort((a,b)=>a-b);
    const percentile=p=>Number(sorted[Math.max(0,Math.ceil(sorted.length*p)-1)].toFixed(4));
    return {n:sorted.length,p50Ms:percentile(.5),p95Ms:percentile(.95),maxMs:percentile(1)};
  }
  return {
    schemaVersion:1,generatedAt:new Date().toISOString(),
    scope:'Author-built synthetic text corpus; positive means an expected suspicious pattern, not confirmed malware. Benign challenges intentionally measure false positives. Timings exclude startup, rule loading, disk traversal, UI and LLMs. Not an independent detection or editor-responsiveness evaluation.',
    environment:{node:process.version,platform:process.platform,arch:process.arch,cpu:os.cpus()[0]?.model},
    identity:{packageVersion:require('../package.json').version,corpusSha256:hash(corpusBytes),rulesSha256:digestTree(path.join(root,'rules')),sourceSha256:digestTree(path.join(root,'src')),lockfileSha256:hash(fs.readFileSync(path.join(root,'package-lock.json')))},
    rulesLoaded:loaded.count,cases:results.length,iterations,matrix,byRule,contractFailures,
    timing:{file:distribution(timings),corpusPass:distribution(passes)},results
  };
}

module.exports = {benchmark};
if (require.main === module) {
  const result=benchmark(Number(process.env.FIG_BENCH_ITERATIONS || 20));
  process.stdout.write(JSON.stringify(result,null,2)+'\n');
  if(result.contractFailures) process.exitCode=1;
}

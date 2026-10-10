const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { executeRule } = require('../../out/rules/rule-engine');
const { RuleLoader } = require('../../out/rules/rule-loader');
const { Scanner } = require('../../out/scanner/scanner');

function validRule(id = 'synthetic-rule') {
  return {
    id, name: 'Synthetic rule', severity: 'medium', confidence: 'high',
    description: 'Inert marker for rule validation.',
    appliesTo: { filePatterns: ['**/*.js'], languages: ['javascript'] },
    matchers: [{ id: 'marker', type: 'string', pattern: 'INERT_MARKER' }],
    condition: { type: 'any', of: ['marker'] },
  };
}

suite('Rule path restrictions regression', () => {
  const cases = [
    ['package filename at root', '**/package.json', 'package.json', true],
    ['package filename nested', '**/package.json', '/repo/packages/a/package.json', true],
    ['same extension wrong filename', '**/package.json', '/repo/unrelated.json', false],
    ['workflow folder', '**/.github/workflows/*.yml', '/repo/.github/workflows/ci.yml', true],
    ['same basename outside workflow folder', '**/.github/workflows/*.yml', '/repo/ci.yml', false],
    ['sibling folder boundary', '**/allowed/*.js', '/repo/disallowed/test.js', false],
    ['exact folder', '**/allowed/*.js', '/repo/allowed/test.js', true],
    ['single star does not cross folder', '**/allowed/*.js', '/repo/allowed/nested/test.js', false],
    ['globstar crosses folder', '**/allowed/**/*.js', '/repo/allowed/nested/test.js', true],
    ['path pattern is not a basename fallback', '**/allowed/**/README', '/repo/README', false],
    ['relative path literal', 'allowed/test.js', 'allowed/test.js', true],
    ['relative path stays anchored', 'allowed/test.js', 'other/allowed/test.js', false],
    ['absolute path literal', '/repo/allowed/test.js', '/repo/allowed/test.js', true],
    ['absolute path stays anchored', '/repo/allowed/test.js', '/other/allowed/test.js', false],
    ['basename glob at any depth', '*.js', '/repo/nested/test.js', true],
    ['basename literal at any depth', 'package.json', '/repo/nested/package.json', true],
    ['basename literal excludes another json', 'package.json', '/repo/another.json', false],
    ['hidden basename literal', '**/.gitconfig', '/repo/.gitconfig', true],
    ['hidden directory glob', '**/.git/hooks/*', '/repo/.git/hooks/pre-commit', true],
    ['wildcard inside hidden folder', '**/*.js', '/repo/.hidden/test.js', true],
    ['Windows path separators', '**/allowed/*.js', 'C:\\repo\\allowed\\test.js', true],
    ['Windows pattern separators', '**\\allowed\\*.js', 'C:\\repo\\allowed\\test.js', true],
    ['Windows folder boundary', '**\\allowed\\*.js', 'C:\\repo\\disallowed\\test.js', false],
    ['leading current-directory path', 'allowed/*.js', './allowed/test.js', true],
    ['leading current-directory pattern', './allowed/*.js', 'allowed/test.js', true],
    ['explicit current-directory basename', './package.json', 'package.json', true],
    ['explicit current-directory basename stays anchored', './package.json', 'nested/package.json', false],
    ['parent segments keep real folder boundary', '**/allowed/*.js', '/repo/allowed/../other/test.js', false],
    ['redundant separators', '**/allowed/*.js', '/repo//allowed//test.js', true],
  ];
  for (const [name, pattern, filePath, expected] of cases) {
    test(name, () => {
      const rule = validRule();
      rule.appliesTo.filePatterns = [pattern];
      assert.equal(executeRule(rule, 'INERT_MARKER', filePath) !== null, expected);
    });
  }

  test('alternatives are OR-ed without widening a failed alternative', () => {
    const rule = validRule();
    rule.appliesTo.filePatterns = ['**/package.json', '**/allowed/*.js'];
    assert.ok(executeRule(rule, 'INERT_MARKER', '/repo/allowed/test.js'));
    assert.equal(executeRule(rule, 'INERT_MARKER', '/repo/another.json'), null);
  });
});

suite('Runtime rule schema regression', () => {
  let directory;
  setup(() => { directory = fs.mkdtempSync(path.join(os.tmpdir(), 'fig-rule-schema-')); });
  teardown(() => { fs.rmSync(directory, { recursive: true, force: true }); });

  function writeRule(rule, name = 'rule.json') {
    fs.writeFileSync(path.join(directory, name), JSON.stringify(rule));
  }

  const invalidCases = [
    ['null rule', () => null],
    ['array rule', () => []],
    ['non-string id', r => ({ ...r, id: 42 })],
    ['empty id', r => ({ ...r, id: ' ' })],
    ['non-string name', r => ({ ...r, name: {} })],
    ['empty name', r => ({ ...r, name: ' ' })],
    ['invalid severity', r => ({ ...r, severity: 'urgent' })],
    ['non-string description', r => ({ ...r, description: {} })],
    ['null description', r => ({ ...r, description: null })],
    ['non-string confidence', r => ({ ...r, confidence: 42 })],
    ['non-string version', r => ({ ...r, version: 1 })],
    ['non-string category', r => ({ ...r, category: [] })],
    ['non-string campaign', r => ({ ...r, campaign: false })],
    ['invalid references elements', r => ({ ...r, references: [42] })],
    ['invalid tags elements', r => ({ ...r, tags: [null] })],
    ['non-object appliesTo', r => ({ ...r, appliesTo: 'all' })],
    ['array appliesTo', r => ({ ...r, appliesTo: [] })],
    ['null filePatterns', r => ({ ...r, appliesTo: { filePatterns: null } })],
    ['non-array filePatterns', r => ({ ...r, appliesTo: { filePatterns: '**/*.js' } })],
    ['numeric filePatterns entry', r => ({ ...r, appliesTo: { filePatterns: [42] } })],
    ['empty filePatterns entry', r => ({ ...r, appliesTo: { filePatterns: [''] } })],
    ['oversized glob', r => ({ ...r, appliesTo: { filePatterns: ['x'.repeat(65537)] } })],
    ['non-array languages', r => ({ ...r, appliesTo: { languages: 'javascript' } })],
    ['non-string language entry', r => ({ ...r, appliesTo: { languages: [false] } })],
    ['empty language entry', r => ({ ...r, appliesTo: { languages: [' '] } })],
    ['null matchers entry', r => ({ ...r, matchers: [null] })],
    ['empty matchers', r => ({ ...r, matchers: [] })],
    ['duplicate matcher ids', r => ({ ...r, matchers: [r.matchers[0], { ...r.matchers[0], pattern: 'OTHER' }] })],
    ['unsupported matcher type', r => ({ ...r, matchers: [{ id: 'marker', type: 'file-structure' }] })],
    ['string pattern type', r => ({ ...r, matchers: [{ id: 'marker', type: 'string', pattern: 42 }] })],
    ['string-any elements', r => ({ ...r, matchers: [{ id: 'marker', type: 'string-any', patterns: [42] }] })],
    ['string-any case flag type', r => ({ ...r, matchers: [{ id: 'marker', type: 'string-any', patterns: ['INERT_MARKER'], caseSensitive: 'false' }] })],
    ['string context type', r => ({ ...r, matchers: [{ ...r.matchers[0], context: {} }] })],
    ['invalid regex', r => ({ ...r, matchers: [{ id: 'marker', type: 'regex', pattern: '[' }] })],
    ['regex flags type', r => ({ ...r, matchers: [{ id: 'marker', type: 'regex', pattern: 'INERT_MARKER', flags: [] }] })],
    ['invalid regex flags', r => ({ ...r, matchers: [{ id: 'marker', type: 'regex', pattern: 'INERT_MARKER', flags: 'ii' }] })],
    ['invalid legacy ast regex', r => ({ ...r, matchers: [{ id: 'marker', type: 'ast', pattern: '[' }] })],
    ['ast language type', r => ({ ...r, matchers: [{ id: 'marker', type: 'ast', pattern: 'eval_call', language: [] }] })],
    ['condition is array', r => ({ ...r, condition: [] })],
    ['unsupported compound condition', r => ({ ...r, condition: { type: 'any', of: ['marker'], and: { type: 'all', of: ['marker'] } } })],
    ['unknown condition field', r => ({ ...r, condition: { type: 'any', of: ['marker'], typo: true } })],
    ['threshold minimum on any condition', r => ({ ...r, condition: { type: 'any', of: ['marker'], minimum: 1 } })],
    ['empty condition references', r => ({ ...r, condition: { type: 'any', of: [] } })],
    ['non-string condition reference', r => ({ ...r, condition: { type: 'any', of: [42] } })],
    ['unknown condition reference', r => ({ ...r, condition: { type: 'any', of: ['other'] } })],
    ['duplicate condition references', r => ({ ...r, condition: { type: 'threshold', of: ['marker', 'marker'], minimum: 2 } })],
    ['non-object MITRE metadata', r => ({ ...r, mitre: 'Execution' })],
    ['missing MITRE fields', r => ({ ...r, mitre: { tactic: 'Execution' } })],
    ['non-string MITRE field', r => ({ ...r, mitre: { tactic: {}, technique: 'T0000', name: 'Synthetic' } })],
    ['non-string MITRE name', r => ({ ...r, mitre: { tactic: 'Execution', technique: 'T0000', name: [] } })],
    ['non-object remediation', r => ({ ...r, remediation: 'Review' })],
    ['non-string remediation message', r => ({ ...r, remediation: { message: {}, actions: ['review'] } })],
    ['non-array remediation actions', r => ({ ...r, remediation: { message: 'Review', actions: 'review' } })],
    ['non-string remediation action', r => ({ ...r, remediation: { message: 'Review', actions: [42] } })],
    ['invalid remediation references', r => ({ ...r, remediation: { message: 'Review', actions: ['review'], references: [null] } })],
  ];
  for (const minimum of [null, '1', 0, -1, 0.5, 2, Number.MAX_SAFE_INTEGER + 1]) {
    invalidCases.push([`invalid threshold minimum ${minimum}`, r => ({ ...r, condition: { type: 'threshold', of: ['marker'], minimum } })]);
  }
  for (const threshold of [null, '3', -1]) {
    invalidCases.push([`invalid entropy threshold ${threshold}`, r => ({ ...r, matchers: [{ id: 'marker', type: 'entropy', threshold, minLength: 5 }] })]);
  }
  for (const minLength of [null, '5', 0, -1, 0.5, Number.MAX_SAFE_INTEGER + 1]) {
    invalidCases.push([`invalid entropy minLength ${minLength}`, r => ({ ...r, matchers: [{ id: 'marker', type: 'entropy', threshold: 3, minLength }] })]);
  }
  for (const [name, transform] of invalidCases) {
    test(`rejects ${name} with a visible error and keeps the valid sibling`, () => {
      writeRule(transform(validRule('invalid')), 'a-invalid.json');
      writeRule(validRule('valid-sibling'), 'b-valid.json');
      const loader = new RuleLoader();
      loader.loadFromDirectory(directory);
      assert.deepEqual(loader.getRules().map(r => r.id), ['valid-sibling']);
      assert.equal(loader.getErrors().length, 1);
      assert.ok(loader.getErrors()[0].includes('a-invalid.json'), 'error identifies the source file');
      assert.ok(executeRule(loader.getRules()[0], 'INERT_MARKER', '/repo/test.js'));
    });
  }

  test('rejects nonfinite JSON numeric overflow before scanning', () => {
    for (const [label, makeRule] of [
      ['condition', r => ({ ...r, condition: { type: 'threshold', of: ['marker'], minimum: 'OVERFLOW' } })],
      ['entropy', r => ({ ...r, matchers: [{ id: 'marker', type: 'entropy', threshold: 'OVERFLOW', minLength: 5 }] })],
      ['length', r => ({ ...r, matchers: [{ id: 'marker', type: 'entropy', threshold: 3, minLength: 'OVERFLOW' }] })],
    ]) {
      fs.writeFileSync(path.join(directory, `${label}.json`), JSON.stringify(makeRule(validRule(label))).replace('"OVERFLOW"', '1e400'));
    }
    const loader = new RuleLoader();
    loader.loadFromDirectory(directory);
    assert.equal(loader.getRules().length, 0);
    assert.equal(loader.getErrors().length, 3);
  });

  test('duplicate rule IDs across loads cannot replace the first accepted rule', () => {
    const loader = new RuleLoader();
    writeRule(validRule('same-id'));
    loader.loadFromDirectory(directory);
    writeRule({ ...validRule('same-id'), name: 'Replacement' });
    loader.loadFromDirectory(directory);
    assert.equal(loader.getRules().length, 1);
    assert.equal(loader.getRules()[0].name, 'Synthetic rule');
    assert.match(loader.getErrors()[0], /duplicate.*same-id/i);
    loader.clear();
    loader.loadFromDirectory(directory);
    assert.equal(loader.getRules().length, 1);
    assert.equal(loader.getRules()[0].name, 'Replacement');
    assert.deepEqual(loader.getErrors(), []);
  });

  test('an invalid earlier rule does not reserve a valid sibling ID', () => {
    writeRule({ ...validRule('same-id'), appliesTo: { filePatterns: [42] } }, 'a-invalid.json');
    writeRule(validRule('same-id'), 'b-valid.json');
    const loader = new RuleLoader();
    loader.loadFromDirectory(directory);
    assert.equal(loader.getRules().length, 1);
    assert.equal(loader.getRules()[0].id, 'same-id');
    assert.ok(executeRule(loader.getRules()[0], 'INERT_MARKER', '/repo/test.js'));
    assert.equal(loader.getErrors().length, 1);
  });

  test('minimal documented rules receive safe presentation and applicability defaults', () => {
    const rule = validRule();
    delete rule.description;
    delete rule.confidence;
    rule.appliesTo = {};
    writeRule(rule);
    const loader = new RuleLoader();
    loader.loadFromDirectory(directory);
    assert.deepEqual(loader.getErrors(), []);
    const loaded = loader.getRules()[0];
    assert.deepEqual(loaded.appliesTo, { languages: [], filePatterns: [] });
    const threat = executeRule(loaded, 'INERT_MARKER', '/repo/test.js');
    assert.equal(threat.message, rule.name);
    assert.equal(threat.confidence, 'medium');
    assert.doesNotThrow(() => threat.message.substring(0, 100));
  });

  test('threshold checks a real boundary with distinct tokens', () => {
    const rule = validRule();
    rule.matchers = ['ALPHA_TOKEN', 'BETA_TOKEN', 'GAMMA_TOKEN'].map((pattern, i) => ({ id: `m${i}`, type: 'string', pattern }));
    rule.condition = { type: 'threshold', of: ['m0', 'm1', 'm2'], minimum: 2 };
    writeRule(rule);
    const loader = new RuleLoader();
    loader.loadFromDirectory(directory);
    assert.deepEqual(loader.getErrors(), []);
    assert.equal(executeRule(loader.getRules()[0], 'ALPHA_TOKEN', 'test.js'), null);
    assert.ok(executeRule(loader.getRules()[0], 'ALPHA_TOKEN BETA_TOKEN', 'test.js'));
    assert.ok(executeRule(loader.getRules()[0], 'ALPHA_TOKEN BETA_TOKEN GAMMA_TOKEN', 'test.js'));
  });

  test('valid optional metadata and supported matcher variants survive validation', () => {
    const variants = [
      [{ id: 'marker', type: 'string', pattern: 'INERT_MARKER', context: 'file' }, 'INERT_MARKER'],
      [{ id: 'marker', type: 'string-any', patterns: ['inert_marker'], caseSensitive: false, context: 'strings' }, 'INERT_MARKER'],
      [{ id: 'marker', type: 'regex', pattern: 'inert_marker', flags: 'i' }, 'INERT_MARKER'],
      [{ id: 'marker', type: 'entropy', threshold: 0, minLength: 1, context: 'string_literals' }, '"a"'],
      [{ id: 'marker', type: 'ast', pattern: 'eval_call', language: 'javascript' }, 'eval("inert text")'],
      [{ id: 'marker', type: 'ast', pattern: 'INERT_MARKER', language: 'javascript' }, 'INERT_MARKER'],
      [{ id: 'marker', type: 'ast', pattern: '__proto__' }, '__proto__'],
      [{ id: 'marker', type: 'ast', pattern: 'constructor' }, 'constructor'],
    ];
    for (const [index, [matcher]] of variants.entries()) {
      writeRule({ ...validRule(`variant-${index}`), matchers: [matcher],
        version: '1.0.0', category: 'synthetic', campaign: 'fixture', tags: ['fixture'],
        references: ['https://example.invalid/fixture'],
        mitre: { tactic: 'Execution', technique: 'T0000', name: 'Synthetic' },
        remediation: { message: 'Review the inert text', actions: ['review'], references: [] },
      }, `${index}.json`);
    }
    const loader = new RuleLoader();
    loader.loadFromDirectory(directory);
    assert.deepEqual(loader.getErrors(), []);
    assert.equal(loader.getRules().length, variants.length);
    for (const [index, [, content]] of variants.entries()) {
      const rule = loader.getRules().find(r => r.id === `variant-${index}`);
      const threat = executeRule(rule, content, 'test.js');
      assert.ok(threat, `variant ${index} matches inert text`);
      assert.deepEqual(threat.remediation.actions, ['review']);
      assert.equal(threat.mitre.tactic, 'Execution');
    }
  });

  test('all bundled rules remain valid and load exactly once', () => {
    const loader = new RuleLoader();
    loader.loadFromDirectory(path.resolve(__dirname, '../../rules'));
    assert.deepEqual(loader.getErrors(), []);
    assert.equal(loader.getRules().length, 53);
    assert.equal(new Set(loader.getRules().map(r => r.id)).size, 53);
  });

  test('Scanner reports invalid custom rules while scanning with valid bundled and custom siblings', () => {
    writeRule({ ...validRule('invalid-custom'), appliesTo: { filePatterns: [42] } }, 'a-invalid.json');
    writeRule(validRule('valid-custom'), 'b-valid.json');
    const scanner = new Scanner();
    const result = scanner.loadRules(path.resolve(__dirname, '../../rules'), directory);
    assert.equal(result.count, 54);
    assert.equal(result.errors.length, 1);
    const scan = scanner.scanFile('/repo/synthetic.js', 'const marker = "INERT_MARKER";');
    assert.equal(scan.status, 'scanned');
    assert.ok(scan.threats.some(t => t.ruleId === 'valid-custom'));
  });
});

suite('Bundled compound condition regression', () => {
  const rulesDir = path.resolve(__dirname, '../../rules/github-actions');
  const artifact = JSON.parse(fs.readFileSync(path.join(rulesDir, 'artifact-poisoning.json'), 'utf8'));
  const pullRequest = JSON.parse(fs.readFileSync(path.join(rulesDir, 'pull-request-target.json'), 'utf8'));
  const file = '/repo/.github/workflows/fixture.yml';
  const download = 'uses: actions/download-artifact@v4';

  test('artifact download alone is insufficient', () => {
    assert.equal(executeRule(artifact, download, file), null);
  });
  for (const [name, action] of [
    ['execution', 'bash ./artifact/setup.sh'],
    ['executable permission', 'chmod +x ./artifact/setup.sh'],
    ['shell source', 'source ./artifact/setup.sh'],
  ]) {
    test(`artifact ${name} alone is insufficient`, () => {
      assert.equal(executeRule(artifact, action, file), null);
    });
    test(`artifact download plus ${name} matches`, () => {
      const finding = executeRule(artifact, `${download}\n${action}`, file);
      assert.equal(finding?.ruleId, 'gha-artifact-poisoning');
      assert.equal(finding.matchedStrings.length, 2);
    });
  }

  test('pull_request_target trigger alone is insufficient', () => {
    assert.equal(executeRule(pullRequest, 'pull_request_target:', file), null);
  });
  for (const [name, checkout] of [
    ['head.sha', 'uses: actions/checkout@v4\nref: ${{ github.event.pull_request.head.sha }}'],
    ['head.ref', 'uses: actions/checkout@v4\nref: ${{ github.event.pull_request.head.ref }}'],
    ['head_ref', 'uses: actions/checkout@v4\n  with:\n    ref: ${{ github.head_ref }}'],
  ]) {
    test(`PR checkout ${name} alone is insufficient`, () => {
      assert.equal(executeRule(pullRequest, checkout, file), null);
    });
    test(`pull_request_target plus checkout ${name} matches`, () => {
      const finding = executeRule(pullRequest, `pull_request_target:\n${checkout}`, file);
      assert.equal(finding?.ruleId, 'gha-pull-request-target-risk');
      assert.equal(finding.matchedStrings.length, 2);
    });
  }
});

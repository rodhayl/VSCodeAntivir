const assert = require('assert');
const {Scanner} = require('../../out/scanner/scanner');
const {runNpmAuditEngine} = require('../../out/scanner/engines/npm-audit-engine');
const finding = spec => runNpmAuditEngine(JSON.stringify({dependencies:{'event-stream':spec}}), 'package.json').find(t=>t.ruleId==='npm-known-bad-package');
suite('Local package-manifest safety', () => {
  for (const pkg of [null, [], 1, {scripts:[]}, {scripts:{install:42}}, {dependencies:{axios:null}}, {optionalDependencies: false}, {peerDependencies:{react:{}}}]) {
    test(`invalid structure is explicitly incomplete: ${JSON.stringify(pkg)}`, () => {
      const result = new Scanner().scanFile('package.json', JSON.stringify(pkg));
      assert.strictEqual(result.status, 'error'); assert(result.detail);
      assert.deepStrictEqual(runNpmAuditEngine(JSON.stringify(pkg), 'package.json'), []);
    });
  }
  test('exact indicator wording never claims blocking or installed-version verification', () => {
    const match=finding('3.3.6'); assert(match); assert.strictEqual(match.severity, 0);
    assert(!match.message.includes('BLOCKED')); assert(match.message.includes('installed contents were not verified'));
  });
  for (const spec of ['^3.3.5', '~3.3.5', '>=3.0.0 <4', '3.x', '*', '3.3.5 || 3.3.6']) test(`range ${spec} is a potential declaration match`, () => {
    const match=finding(spec); assert(match); assert.strictEqual(match.confidence,'medium'); assert(match.message.includes('may include'));
  });
  for (const spec of ['>3.3.6', '3.3.60', '3.3.6-beta.1', '^4.0.0', 'file:../event-stream', 'https://example.invalid/package.tgz']) test(`nonmatching or unresolved spec ${spec} is not asserted compromised`, () => assert(!finding(spec)));
  test('npm alias is inspected as its target declaration', () => {
    const results=runNpmAuditEngine('{"dependencies":{"alias":"npm:event-stream@3.3.6"}}','package.json');
    assert(results.some(t=>t.ruleId==='npm-known-bad-package' && t.message.includes('alias')));
  });
  test('optional and peer declarations are included without installing anything', () => {
    for (const field of ['optionalDependencies','peerDependencies']) assert(runNpmAuditEngine(JSON.stringify({[field]:{'event-stream':'3.3.6'}}),'package.json').some(t=>t.ruleId==='npm-known-bad-package'));
  });
});

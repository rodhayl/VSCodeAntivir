const assert = require('assert');

const { escapeHtml, getSecurityScore, getTacticIcon, defangUrl, extractFileName } = require('../../out/providers/provider-utils');

suite('Provider Utils - escapeHtml', () => {
  test('empty string returns empty', () => {
    assert.strictEqual(escapeHtml(''), '');
  });

  test('escapes ampersand', () => {
    assert.strictEqual(escapeHtml('a&b'), 'a&amp;b');
  });

  test('escapes angle brackets', () => {
    assert.strictEqual(escapeHtml('<script>'), '&lt;script&gt;');
  });

  test('escapes double quotes', () => {
    assert.strictEqual(escapeHtml('say "hello"'), 'say &quot;hello&quot;');
  });

  test('escapes multiple characters', () => {
    assert.strictEqual(escapeHtml('<a href="x&y">'), '&lt;a href=&quot;x&amp;y&quot;&gt;');
  });

  test('leaves normal text untouched', () => {
    assert.strictEqual(escapeHtml('hello world 123'), 'hello world 123');
  });
});

suite('Provider Utils - getSecurityScore', () => {
  function makeThreat(severity) {
    return {
      ruleId: 'test',
      ruleName: 'Test',
      severity,
      message: 'test',
      filePath: 'test.js',
      location: { startLine: 0, startCol: 0, endLine: 0, endCol: 0 },
    };
  }

  test('empty threat map gives score 100', () => {
    const map = new Map();
    const { score, bySeverity } = getSecurityScore(map);
    assert.strictEqual(score, 100);
    assert.strictEqual(bySeverity.critical, 0);
    assert.strictEqual(bySeverity.high, 0);
    assert.strictEqual(bySeverity.medium, 0);
    assert.strictEqual(bySeverity.low, 0);
    assert.strictEqual(bySeverity.info, 0);
  });

  test('one critical threat reduces score by 25', () => {
    const map = new Map([['file.js', [makeThreat(0)]]]);
    const { score, bySeverity } = getSecurityScore(map);
    assert.strictEqual(score, 75);
    assert.strictEqual(bySeverity.critical, 1);
  });

  test('one high threat reduces score by 15', () => {
    const map = new Map([['file.js', [makeThreat(1)]]]);
    const { score } = getSecurityScore(map);
    assert.strictEqual(score, 85);
  });

  test('one medium threat reduces score by 8', () => {
    const map = new Map([['file.js', [makeThreat(2)]]]);
    const { score } = getSecurityScore(map);
    assert.strictEqual(score, 92);
  });

  test('one low threat reduces score by 3', () => {
    const map = new Map([['file.js', [makeThreat(3)]]]);
    const { score } = getSecurityScore(map);
    assert.strictEqual(score, 97);
  });

  test('one info threat reduces score by 1', () => {
    const map = new Map([['file.js', [makeThreat(4)]]]);
    const { score } = getSecurityScore(map);
    assert.strictEqual(score, 99);
  });

  test('score floors at 0', () => {
    const threats = Array(10).fill(makeThreat(0));
    const map = new Map([['file.js', threats]]);
    const { score } = getSecurityScore(map);
    assert.strictEqual(score, 0);
  });

  test('multiple files aggregated', () => {
    const map = new Map([
      ['a.js', [makeThreat(0)]],
      ['b.js', [makeThreat(1)]],
    ]);
    const { score, bySeverity } = getSecurityScore(map);
    assert.strictEqual(score, 60); // 100 - 25 - 15
    assert.strictEqual(bySeverity.critical, 1);
    assert.strictEqual(bySeverity.high, 1);
  });
});

suite('Provider Utils - getTacticIcon', () => {
  test('Initial Access icon', () => {
    assert.strictEqual(getTacticIcon('Initial Access'), '🔓');
  });

  test('Execution icon', () => {
    assert.strictEqual(getTacticIcon('Execution'), '⚡');
  });

  test('Persistence icon', () => {
    assert.strictEqual(getTacticIcon('Persistence'), '📌');
  });

  test('Defense Evasion icon', () => {
    assert.strictEqual(getTacticIcon('Defense Evasion'), '🛡️');
  });

  test('Credential Access icon', () => {
    assert.strictEqual(getTacticIcon('Credential Access'), '🔑');
  });

  test('Discovery icon', () => {
    assert.strictEqual(getTacticIcon('Discovery'), '🔍');
  });

  test('Collection icon', () => {
    assert.strictEqual(getTacticIcon('Collection'), '📦');
  });

  test('Exfiltration icon', () => {
    assert.strictEqual(getTacticIcon('Exfiltration'), '📤');
  });

  test('Command and Control icon', () => {
    assert.strictEqual(getTacticIcon('Command and Control'), '📡');
  });

  test('Other icon', () => {
    assert.strictEqual(getTacticIcon('Other'), '❓');
  });

  test('unknown tactic returns default icon', () => {
    assert.strictEqual(getTacticIcon('SomeNewTactic'), '❓');
  });
});

suite('Provider Utils - defangUrl', () => {
  test('defangs http to hxxp', () => {
    assert.strictEqual(defangUrl('http://evil.com'), 'hxxp://evil[.]com');
  });

  test('defangs https to hxxps', () => {
    assert.strictEqual(defangUrl('https://evil.com/payload'), 'hxxps://evil[.]com/payload');
  });

  test('defangs all dots', () => {
    assert.strictEqual(defangUrl('http://a.b.c.d'), 'hxxp://a[.]b[.]c[.]d');
  });

  test('no URL returns text with dots defanged', () => {
    assert.strictEqual(defangUrl('no url here'), 'no url here');
  });

  test('multiple URLs defanged', () => {
    const input = 'visit http://a.com or https://b.org';
    const result = defangUrl(input);
    assert(result.includes('hxxp'));
    assert(!result.includes('http://'));
    assert(!result.includes('https://'));
  });
});

suite('Provider Utils - extractFileName', () => {
  test('forward slash path', () => {
    assert.strictEqual(extractFileName('src/utils/helper.ts'), 'helper.ts');
  });

  test('backslash path', () => {
    assert.strictEqual(extractFileName('C:\\Users\\test\\file.js'), 'file.js');
  });

  test('mixed slashes', () => {
    assert.strictEqual(extractFileName('src\\utils/file.ts'), 'file.ts');
  });

  test('no slashes returns input', () => {
    assert.strictEqual(extractFileName('file.js'), 'file.js');
  });

  test('trailing slash falls back to full path', () => {
    assert.strictEqual(extractFileName('dir/'), 'dir/');
  });
});

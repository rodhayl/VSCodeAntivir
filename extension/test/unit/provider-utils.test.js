const assert = require('assert');

const { escapeHtml, summarizeFindings, getTacticIcon, extractFileName } = require('../../out/providers/provider-utils');

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

suite('Provider Utils - summarizeFindings', () => {
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

  test('empty map reports zero findings, not a safety score', () => {
    const map = new Map();
    const { count, bySeverity } = summarizeFindings(map);
    assert.strictEqual(count, 0);
    assert.strictEqual(bySeverity.critical, 0);
    assert.strictEqual(bySeverity.high, 0);
    assert.strictEqual(bySeverity.medium, 0);
    assert.strictEqual(bySeverity.low, 0);
    assert.strictEqual(bySeverity.info, 0);
  });

  test('critical finding is counted', () => {
    const map = new Map([['file.js', [makeThreat(0)]]]);
    const { count, bySeverity } = summarizeFindings(map);
    assert.strictEqual(count, 1);
    assert.strictEqual(bySeverity.critical, 1);
  });

  test('high finding is counted', () => {
    const map = new Map([['file.js', [makeThreat(1)]]]);
    const { count } = summarizeFindings(map);
    assert.strictEqual(count, 1);
  });

  test('medium finding is counted', () => {
    const map = new Map([['file.js', [makeThreat(2)]]]);
    const { count } = summarizeFindings(map);
    assert.strictEqual(count, 1);
  });

  test('low finding is counted', () => {
    const map = new Map([['file.js', [makeThreat(3)]]]);
    const { count } = summarizeFindings(map);
    assert.strictEqual(count, 1);
  });

  test('info finding is counted', () => {
    const map = new Map([['file.js', [makeThreat(4)]]]);
    const { count } = summarizeFindings(map);
    assert.strictEqual(count, 1);
  });

  test('count retains all ten findings', () => {
    const threats = Array(10).fill(makeThreat(0));
    const map = new Map([['file.js', threats]]);
    const { count } = summarizeFindings(map);
    assert.strictEqual(count, 10);
  });

  test('multiple files aggregated', () => {
    const map = new Map([
      ['a.js', [makeThreat(0)]],
      ['b.js', [makeThreat(1)]],
    ]);
    const { count, bySeverity } = summarizeFindings(map);
    assert.strictEqual(count, 2);
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

const path = require('path');
const Mocha = require('mocha');

function findTestFiles(dir) {
  const results = [];
  const entries = require('fs').readdirSync(dir, { withFileTypes: true });
  for (const entry of entries) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) results.push(...findTestFiles(full));
    else if (entry.name.endsWith('.test.js')) results.push(full);
  }
  return results;
}

module.exports = function run() {
  const mocha = new Mocha({ ui: 'tdd', color: true, timeout: 10000 });
  const testsRoot = path.resolve(__dirname, 'unit');
  const files = findTestFiles(testsRoot);
  files.forEach(f => mocha.addFile(f));

  return new Promise((resolve, reject) => {
    mocha.run(failures => {
      if (failures > 0) reject(new Error(`${failures} tests failed.`));
      else resolve();
    });
  });
};

const path = require('path');
const Mocha = require('mocha');
const fs = require('fs');

function findTestFiles(dir) {
  const results = [];
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) results.push(...findTestFiles(full));
    else if (entry.name.endsWith('.test.js')) results.push(full);
  }
  return results;
}

function run() {
  const mocha = new Mocha({ ui: 'tdd', color: true, timeout: 30000 });
  const testsRoot = path.resolve(__dirname);

  return new Promise((resolve, reject) => {
    try {
      const files = findTestFiles(testsRoot);
      files.forEach(f => mocha.addFile(f));
      mocha.run(failures => {
        if (failures > 0) {
          reject(new Error(`${failures} tests failed.`));
        } else {
          resolve();
        }
      });
    } catch (err) {
      reject(err);
    }
  });
}

module.exports = { run };

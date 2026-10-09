const assert = require('assert');
const {benchmark} = require('../benchmark');

suite('Reproducible synthetic corpus', () => {
  test('all cases are scanned and required positive patterns remain detected', () => {
    const result=benchmark(1);
    assert.strictEqual(result.cases,20);
    assert.strictEqual(result.rulesLoaded,53);
    assert.strictEqual(result.contractFailures,0);
    assert.strictEqual(result.matrix.errors,0);
    assert.strictEqual(Object.values(result.matrix).reduce((a,b)=>a+b,0),20);
    assert(result.matrix.falsePositive>0,'Benign challenge failures must remain visible rather than omitted');
    for(const value of Object.values(result.identity).slice(1)) assert(/^[a-f0-9]{64}$/.test(value));
    assert.strictEqual(result.timing.file.n,20);
  });
  test('invalid workload sizes are refused', () => {
    for(const n of [0,-1,1.5,1001,NaN]) assert.throws(()=>benchmark(n));
  });
});

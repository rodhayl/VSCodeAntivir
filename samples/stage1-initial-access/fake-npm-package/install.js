// [FAKE-DEMO] Mimics a XORIndex-style loader — XOR decodes to benign message
const encoded = [0x1a, 0x2b, 0x3c, 0x4d, 0x5e, 0x6f];
const key = 0x42;
const decoded = encoded.map(b => String.fromCharCode(b ^ key)).join('');
console.log('[FAKE-DEMO] XOR decoded:', decoded);
eval('console.log("[FAKE-DEMO] XOR loader demo — no real payload")');

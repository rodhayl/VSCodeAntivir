// [FAKE-DEMO] Mimics a HexEval-style loader — decodes hex to benign message only
// In real BeaverTail: this would decode and eval() a malicious payload

const hexPayload = '5b46414b452d44454d4f5d20506179';
const decoded = Buffer.from(hexPayload, 'hex').toString('utf-8');
console.log('[FAKE-DEMO] Decoded payload:', decoded);

// Real BeaverTail would do: eval(decoded)
// We just log it instead
eval('console.log("[FAKE-DEMO] eval executed safely — this is a demo")');

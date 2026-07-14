// [FAKE-DEMO] This is an INERT educational sample — NOT real malware
// Mimics a JavaScript beaconing agent that collects host fingerprints
// All network calls point to 127.0.0.1:9999

const http = require('http');
const os = require('os');
const { execSync } = require('child_process');

const SERVER_IP = '127.0.0.1';
const SERVER_PORT = 9999;
const AgentId = 'demo-agent-' + Math.random().toString(36).substring(7);
const BEACON_INTERVAL = 30000;

function getSystemInfo() {
  return {
    hostname: os.hostname(),
    platform: os.platform(),
    release: os.release(),
    networkInterfaces: Object.keys(os.networkInterfaces()),
    uptime: os.uptime(),
    agentId: AgentId,
  };
}

function handleCode(code) {
  console.log('[FAKE-DEMO] Would execute attacker code:', code?.substring(0, 50));
  // Real beacon: const child = execSync(code, { detached: true });
}

function beacon() {
  const data = JSON.stringify(getSystemInfo());
  console.log('[FAKE-DEMO] Beacon to', `http://${SERVER_IP}:${SERVER_PORT}/beacon`);
  console.log('[FAKE-DEMO] Payload:', data.substring(0, 80));
}

// [FAKE-DEMO] Periodic beaconing — only logs
setInterval(() => {
  try {
    beacon();
  } catch (e) {
    console.log('[FAKE-DEMO] Beacon error:', e.message);
  }
}, BEACON_INTERVAL);

console.log('[FAKE-DEMO] Beaconing agent initialized — Agent ID:', AgentId);

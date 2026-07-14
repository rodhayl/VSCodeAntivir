const vscode = require('vscode');

function activate(context) {
  const disposable = vscode.commands.registerCommand('clean-extension.hello', () => {
    vscode.window.showInformationMessage('Hello from a clean sample extension');
  });

  context.subscriptions.push(disposable);
}

module.exports = { activate };

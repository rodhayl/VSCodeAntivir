import * as vscode from 'vscode';

export class CodeActionProvider implements vscode.CodeActionProvider {
  static readonly providedCodeActionKinds = [vscode.CodeActionKind.QuickFix];

  provideCodeActions(
    document: vscode.TextDocument,
    range: vscode.Range | vscode.Selection,
    context: vscode.CodeActionContext,
    _token: vscode.CancellationToken
  ): vscode.CodeAction[] {
    const actions: vscode.CodeAction[] = [];

    for (const diagnostic of context.diagnostics) {
      if (diagnostic.source !== 'FakeInterviewGuard') continue;

      const ruleId = String(diagnostic.code || '');

      // 1. Neutralize eval()
      if (ruleId.includes('eval') || diagnostic.message.toLowerCase().includes('eval')) {
        const line = document.lineAt(diagnostic.range.start.line);
        const evalMatch = line.text.match(/\beval\s*\(/);
        if (evalMatch) {
          const fix = new vscode.CodeAction(
            '🛡️ Neutralize eval() call',
            vscode.CodeActionKind.QuickFix
          );
          fix.edit = new vscode.WorkspaceEdit();
          fix.edit.replace(
            document.uri,
            line.range,
            `/* NEUTRALIZED by FakeInterviewGuard */ // ${line.text.trim()}`
          );
          fix.diagnostics = [diagnostic];
          fix.isPreferred = true;
          actions.push(fix);
        }
      }

      // 2. Remove suspicious npm scripts
      if (ruleId.includes('npm-suspicious-script') || ruleId.includes('remove-hook')) {
        const line = document.lineAt(diagnostic.range.start.line);
        if (line.text.includes('preinstall') || line.text.includes('postinstall') || line.text.includes('prestart')) {
          const fix = new vscode.CodeAction(
            '🛡️ Remove suspicious install script',
            vscode.CodeActionKind.QuickFix
          );
          fix.edit = new vscode.WorkspaceEdit();
          // Remove the entire line + trailing comma on previous line if needed
          const deleteRange = new vscode.Range(line.range.start, new vscode.Position(line.lineNumber + 1, 0));
          fix.edit.delete(document.uri, deleteRange);
          fix.diagnostics = [diagnostic];
          fix.isPreferred = true;
          actions.push(fix);
        }
      }

      // 3. Remove auto-execute from tasks.json
      if (ruleId.includes('vscode-task-autoexec')) {
        const line = document.lineAt(diagnostic.range.start.line);
        if (line.text.includes('folderOpen')) {
          const fix = new vscode.CodeAction(
            '🛡️ Remove auto-execute trigger',
            vscode.CodeActionKind.QuickFix
          );
          fix.edit = new vscode.WorkspaceEdit();
          fix.edit.replace(
            document.uri,
            line.range,
            line.text.replace('"folderOpen"', '"default"')
          );
          fix.diagnostics = [diagnostic];
          fix.isPreferred = true;
          actions.push(fix);
        }
      }

      // 4. Defang URLs
      if (ruleId.includes('url') || ruleId.includes('shortener') || ruleId.includes('dangerous-cmd')) {
        const fix = new vscode.CodeAction(
          '🛡️ Defang URLs in this line',
          vscode.CodeActionKind.QuickFix
        );
        const line = document.lineAt(diagnostic.range.start.line);
        let defanged = line.text
          .replace(/https?:\/\//g, (m) => m.replace('http', 'hxxp'))
          .replace(/\./g, '[.]');
        fix.edit = new vscode.WorkspaceEdit();
        fix.edit.replace(document.uri, line.range, defanged);
        fix.diagnostics = [diagnostic];
        actions.push(fix);
      }

      // 5. LLM Explain (on all FIG diagnostics when LLM is available)
      const explainAction = new vscode.CodeAction(
        '🤖 Explain with LLM',
        vscode.CodeActionKind.QuickFix
      );
      explainAction.command = {
        title: 'Explain with LLM',
        command: 'fig.llmExplain',
        arguments: [
          document.uri.fsPath,
          ruleId,
          diagnostic.message,
          document.getText(diagnostic.range),
        ],
      };
      explainAction.diagnostics = [diagnostic];
      actions.push(explainAction);

      // 6. Generic: Show full threat details
      const infoAction = new vscode.CodeAction(
        '🔍 Show threat details',
        vscode.CodeActionKind.QuickFix
      );
      infoAction.command = {
        title: 'Show threat details',
        command: 'fig.showThreatDetails',
        arguments: [diagnostic.message, diagnostic.code],
      };
      infoAction.diagnostics = [diagnostic];
      actions.push(infoAction);
    }

    return actions;
  }
}

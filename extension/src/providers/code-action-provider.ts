import * as vscode from 'vscode';

export class CodeActionProvider implements vscode.CodeActionProvider {
  static readonly providedCodeActionKinds = [vscode.CodeActionKind.QuickFix];

  provideCodeActions(
    document: vscode.TextDocument,
    _range: vscode.Range | vscode.Selection,
    context: vscode.CodeActionContext,
    _token: vscode.CancellationToken
  ): vscode.CodeAction[] {
    const actions: vscode.CodeAction[] = [];
    for (const diagnostic of context.diagnostics) {
      if (diagnostic.source !== 'FakeInterviewGuard') continue;
      const details = new vscode.CodeAction('Show finding details', vscode.CodeActionKind.QuickFix);
      details.command = { title: 'Show finding details', command: 'fig.showThreatDetails', arguments: [diagnostic.message, diagnostic.code] };
      details.diagnostics = [diagnostic];
      actions.push(details);
      if (!vscode.workspace.isTrusted) continue;
      const review = new vscode.CodeAction('Review workspace configuration changes', vscode.CodeActionKind.QuickFix);
      review.command = { title: 'Review workspace configuration changes', command: 'fig.reviewConfiguration' };
      review.diagnostics = [diagnostic];
      actions.push(review);
      const explain = new vscode.CodeAction('Explain with LLM (requires consent)', vscode.CodeActionKind.QuickFix);
      explain.command = { title: 'Explain with LLM', command: 'fig.llmExplain', arguments: [document.uri.fsPath, String(diagnostic.code || ''), diagnostic.message, document.getText(diagnostic.range)] };
      explain.diagnostics = [diagnostic];
      actions.push(explain);
    }
    return actions;
  }
}

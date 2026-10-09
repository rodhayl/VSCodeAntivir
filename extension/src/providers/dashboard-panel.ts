import * as vscode from 'vscode';
import { Threat } from '../scanner/models/threat';
import { severityToString } from '../scanner/models/severity';
import { escapeHtml, extractFileName, summarizeFindings } from './provider-utils';

export class DashboardPanel {
  public static currentPanel: DashboardPanel | undefined;
  private readonly panel: vscode.WebviewPanel;
  private disposables: vscode.Disposable[] = [];
  private disposed = false;

  private constructor(panel: vscode.WebviewPanel) {
    this.panel = panel;
    this.panel.onDidDispose(() => this.dispose(), null, this.disposables);
  }

  static createOrShow(_extensionUri: vscode.Uri): DashboardPanel {
    if (DashboardPanel.currentPanel) {
      DashboardPanel.currentPanel.panel.reveal(vscode.ViewColumn.Two);
      return DashboardPanel.currentPanel;
    }

    const panel = vscode.window.createWebviewPanel(
      'figDashboard',
      'FIG Security Dashboard',
      vscode.ViewColumn.Two,
      { enableScripts: false, localResourceRoots: [] }
    );

    DashboardPanel.currentPanel = new DashboardPanel(panel);
    return DashboardPanel.currentPanel;
  }

  update(threatMap: Map<string, Threat[]>): void {
    const allThreats: Threat[] = [];
    for (const threats of threatMap.values()) {
      allThreats.push(...threats);
    }

    const { bySeverity } = summarizeFindings(threatMap);
    this.panel.webview.html = this.getHtml(allThreats, bySeverity);
  }

  private getHtml(threats: Threat[], bySeverity: Record<string, number>): string {
    const threatRows = threats.map(t => {
      const sev = severityToString(t.severity).toUpperCase();
      const file = extractFileName(t.filePath);
      const isLlm = t.ruleId.startsWith('llm-');
      const icon = isLlm ? '🤖' : '🔍';
      const source = isLlm ? 'LLM' : 'Rule';
      return `<tr>
        <td class="sev-${severityToString(t.severity)}">${sev}</td>
        <td>${icon} ${escapeHtml(t.ruleName)}</td>
        <td>${escapeHtml(file)}:${t.location.startLine + 1}</td>
        <td><span class="source-badge ${isLlm ? 'llm' : 'rule'}">${source}</span> ${escapeHtml(t.message.substring(0, 100))}</td>
      </tr>`;
    }).join('\n');


    return `<!DOCTYPE html>
<html>
<head>
<style>
  body { font-family: var(--vscode-font-family, sans-serif); padding: 20px; color: var(--vscode-foreground); background: var(--vscode-editor-background); }
  h1 { margin: 0 0 20px; }
  .score-container { display: flex; align-items: center; gap: 20px; margin-bottom: 30px; }
  .score { font-size: 48px; font-weight: bold;  }
  .score-label { font-size: 14px; opacity: 0.7; }
  .severity-badges { display: flex; gap: 10px; margin-bottom: 20px; }
  .badge { padding: 6px 14px; border-radius: 4px; font-weight: bold; font-size: 13px; }
  .badge.critical { background: #d32f2f; color: white; }
  .badge.high { background: #f57c00; color: white; }
  .badge.medium { background: #fbc02d; color: black; }
  .badge.low { background: #1976d2; color: white; }
  .badge.info { background: #757575; color: white; }
  table { width: 100%; border-collapse: collapse; margin-top: 10px; }
  th { text-align: left; padding: 8px; border-bottom: 2px solid var(--vscode-panel-border); font-size: 12px; text-transform: uppercase; opacity: 0.7; }
  td { padding: 8px; border-bottom: 1px solid var(--vscode-panel-border); font-size: 13px; }
  .sev-critical { color: #f44336; font-weight: bold; }
  .sev-high { color: #ff9800; font-weight: bold; }
  .sev-medium { color: #fbc02d; }
  .sev-low { color: #2196f3; }
  .sev-info { color: #9e9e9e; }
  .source-badge { display: inline-block; font-size: 10px; padding: 1px 6px; border-radius: 3px; margin-right: 4px; font-weight: bold; }
  .source-badge.rule { background: #1976d2; color: white; }
  .source-badge.llm { background: #7c4dff; color: white; }
</style>
</head>
<body>
  <h1>FakeInterviewGuard Review Dashboard</h1>
  <p>Findings are advisory. This view is not a safety verdict; inspect skipped files and errors in Output.</p>
  <div class="score-container">
    <div>
      <div class="score">${threats.length}</div>
      <div class="score-label">Reported findings</div>
    </div>
    <div class="severity-badges">
      <span class="badge critical">🔴 ${bySeverity.critical} Critical</span>
      <span class="badge high">🟠 ${bySeverity.high} High</span>
      <span class="badge medium">🟡 ${bySeverity.medium} Medium</span>
      <span class="badge low">🔵 ${bySeverity.low} Low</span>
      <span class="badge info">⚪ ${bySeverity.info} Info</span>
    </div>
  </div>
  <h2>Findings (${threats.length})</h2>
  <table>
    <thead><tr><th>Severity</th><th>Rule</th><th>File</th><th>Description</th></tr></thead>
    <tbody>${threatRows || '<tr><td colspan="4" style="text-align:center; padding: 20px;">No reported findings. Unscanned files may remain.</td></tr>'}</tbody>
  </table>
</body>
</html>`;
  }

  dispose(): void {
    if (this.disposed) return;
    this.disposed = true;
    DashboardPanel.currentPanel = undefined;
    this.panel.dispose();
    for (const d of this.disposables) d.dispose();
  }
}

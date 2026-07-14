import * as vscode from 'vscode';
import { QuarantineManager, QuarantinedFile } from './quarantine-manager';

class QuarantineTreeItem extends vscode.TreeItem {
  constructor(
    public readonly label: string,
    public readonly collapsibleState: vscode.TreeItemCollapsibleState,
    public readonly entry?: QuarantinedFile,
  ) {
    super(label, collapsibleState);

    if (entry) {
      const threatCount = entry.threats.length;
      const maxSeverity = entry.threats.reduce((max, t) => 
        t.severity < max ? t.severity : max, entry.threats[0]?.severity || 4);
      
      this.description = `${threatCount} threat${threatCount !== 1 ? 's' : ''} — ${new Date(entry.detectedAt).toLocaleDateString()}`;
      this.tooltip = [
        `Original: ${entry.originalPath}`,
        `Size: ${(entry.size / 1024).toFixed(1)} KB`,
        `Hash: ${entry.hash.substring(0, 16)}...`,
        `Threats: ${entry.threats.map(t => t.ruleName).join(', ')}`,
      ].join('\n');
      
      this.iconPath = new vscode.ThemeIcon('warning', new vscode.ThemeColor('errorForeground'));
      this.contextValue = 'quarantinedFile';
    }
  }
}

export class QuarantineTreeProvider implements vscode.TreeDataProvider<QuarantineTreeItem> {
  private _onDidChangeTreeData = new vscode.EventEmitter<QuarantineTreeItem | undefined | null>();
  readonly onDidChangeTreeData = this._onDidChangeTreeData.event;

  private manager: QuarantineManager;

  constructor(manager: QuarantineManager) {
    this.manager = manager;
    manager.setChangeHandler(() => this.refresh());
  }

  refresh(): void {
    this._onDidChangeTreeData.fire(null);
  }

  getTreeItem(element: QuarantineTreeItem): QuarantineTreeItem {
    return element;
  }

  getChildren(element?: QuarantineTreeItem): QuarantineTreeItem[] {
    if (element) {
      return [];
    }

    const files = this.manager.getQuarantinedFiles();
    
    if (files.length === 0) {
      return [new QuarantineTreeItem('No quarantined files', vscode.TreeItemCollapsibleState.None)];
    }

    return files.map(f => new QuarantineTreeItem(
      f.fileName,
      vscode.TreeItemCollapsibleState.None,
      f
    ));
  }
}

export class QuarantinePanel {
  public static currentPanel: QuarantinePanel | undefined;
  private readonly panel: vscode.WebviewPanel;
  private readonly manager: QuarantineManager;
  private disposables: vscode.Disposable[] = [];

  private constructor(panel: vscode.WebviewPanel, manager: QuarantineManager) {
    this.panel = panel;
    this.manager = manager;
    
    this.panel.onDidDispose(() => this.dispose(), null, this.disposables);
    
    this.panel.webview.onDidReceiveMessage(
      async (message) => {
        switch (message.command) {
          case 'restore':
            await this.manager.restore(message.id);
            this.update();
            break;
          case 'delete':
            await this.manager.deletePermanently(message.id);
            this.update();
            break;
          case 'clearAll':
            await this.manager.clearAll();
            this.update();
            break;
        }
      },
      null,
      this.disposables
    );

    manager.setChangeHandler(() => this.update());
    this.update();
  }

  static createOrShow(extensionUri: vscode.Uri, manager: QuarantineManager): QuarantinePanel {
    if (QuarantinePanel.currentPanel) {
      QuarantinePanel.currentPanel.panel.reveal(vscode.ViewColumn.Two);
      QuarantinePanel.currentPanel.update();
      return QuarantinePanel.currentPanel;
    }

    const panel = vscode.window.createWebviewPanel(
      'figQuarantine',
      'FIG Quarantine Manager',
      vscode.ViewColumn.Two,
      { enableScripts: true }
    );

    QuarantinePanel.currentPanel = new QuarantinePanel(panel, manager);
    return QuarantinePanel.currentPanel;
  }

  update(): void {
    const files = this.manager.getQuarantinedFiles();
    this.panel.webview.html = this.getHtml(files);
  }

  private getHtml(files: QuarantinedFile[]): string {
    const rows = files.map(f => {
      const threats = f.threats.map(t => `<span class="threat-badge">${this.escapeHtml(t.ruleName)}</span>`).join(' ');
      return `
        <tr data-id="${f.id}">
          <td><code>${this.escapeHtml(f.fileName)}</code></td>
          <td><small>${this.escapeHtml(f.originalPath)}</small></td>
          <td>${threats}</td>
          <td>${new Date(f.detectedAt).toLocaleString()}</td>
          <td>
            <button class="btn restore" onclick="restore('${f.id}')">🔄 Restore</button>
            <button class="btn delete" onclick="deleteFile('${f.id}')">🗑️ Delete</button>
          </td>
        </tr>
      `;
    }).join('\n');

    return `<!DOCTYPE html>
<html>
<head>
<style>
  body { font-family: var(--vscode-font-family); padding: 20px; color: var(--vscode-foreground); background: var(--vscode-editor-background); }
  h1 { margin: 0 0 20px; display: flex; align-items: center; gap: 10px; }
  .stats { display: flex; gap: 20px; margin-bottom: 20px; }
  .stat { padding: 10px 20px; background: var(--vscode-input-background); border-radius: 6px; }
  .stat-value { font-size: 24px; font-weight: bold; }
  .stat-label { font-size: 12px; opacity: 0.7; }
  table { width: 100%; border-collapse: collapse; }
  th { text-align: left; padding: 10px; border-bottom: 2px solid var(--vscode-panel-border); font-size: 12px; text-transform: uppercase; opacity: 0.7; }
  td { padding: 10px; border-bottom: 1px solid var(--vscode-panel-border); font-size: 13px; }
  .threat-badge { display: inline-block; background: #d32f2f; color: white; padding: 2px 8px; border-radius: 4px; font-size: 11px; margin: 2px; }
  .btn { border: none; padding: 5px 10px; border-radius: 4px; cursor: pointer; font-size: 12px; margin-right: 5px; }
  .btn.restore { background: #1976d2; color: white; }
  .btn.delete { background: #d32f2f; color: white; }
  .btn.clear-all { background: #f57c00; color: white; margin-bottom: 20px; }
  .empty { text-align: center; padding: 40px; opacity: 0.7; }
</style>
</head>
<body>
  <h1>🛡️ Quarantine Manager</h1>
  <div class="stats">
    <div class="stat">
      <div class="stat-value">${files.length}</div>
      <div class="stat-label">Quarantined Files</div>
    </div>
    <div class="stat">
      <div class="stat-value">${files.reduce((sum, f) => sum + f.threats.length, 0)}</div>
      <div class="stat-label">Total Threats</div>
    </div>
  </div>
  ${files.length > 0 ? `
    <button class="btn clear-all" onclick="clearAll()">🗑️ Clear All Quarantined Files</button>
    <table>
      <thead><tr><th>File</th><th>Original Path</th><th>Threats</th><th>Quarantined</th><th>Actions</th></tr></thead>
      <tbody>${rows}</tbody>
    </table>
  ` : '<div class="empty">✅ No files in quarantine</div>'}
  <script>
    const vscode = acquireVsCodeApi();
    function restore(id) { vscode.postMessage({ command: 'restore', id }); }
    function deleteFile(id) { 
      if (confirm('Permanently delete this file?')) {
        vscode.postMessage({ command: 'delete', id }); 
      }
    }
    function clearAll() {
      if (confirm('Permanently delete ALL quarantined files?')) {
        vscode.postMessage({ command: 'clearAll' });
      }
    }
  </script>
</body>
</html>`;
  }

  private escapeHtml(s: string): string {
    return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
  }

  dispose(): void {
    QuarantinePanel.currentPanel = undefined;
    this.panel.dispose();
    for (const d of this.disposables) d.dispose();
  }
}

import * as vscode from 'vscode';
import * as fs from 'fs';
import * as path from 'path';
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

export class QuarantineTreeProvider implements vscode.TreeDataProvider<QuarantineTreeItem>, vscode.Disposable {
  private _onDidChangeTreeData = new vscode.EventEmitter<QuarantineTreeItem | undefined | null>();
  readonly onDidChangeTreeData = this._onDidChangeTreeData.event;

  private manager: QuarantineManager;
  private changeSubscription: vscode.Disposable;

  constructor(manager: QuarantineManager) {
    this.manager = manager;
    this.changeSubscription = manager.addChangeHandler(() => this.refresh());
  }

  dispose(): void {
    this.changeSubscription.dispose();
    this._onDidChangeTreeData.dispose();
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
    const error = this.manager.getStoreError();
    if (error) {
      const item = new QuarantineTreeItem('Quarantine unavailable', vscode.TreeItemCollapsibleState.None);
      item.tooltip = error;
      return [item];
    }

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
  private disposed = false;
  private actionPending = false;

  private constructor(panel: vscode.WebviewPanel, manager: QuarantineManager) {
    this.panel = panel;
    this.manager = manager;
    
    this.panel.onDidDispose(() => this.dispose(), null, this.disposables);
    
    this.panel.webview.onDidReceiveMessage(
      (message: unknown) => this.handleMessage(message), null, this.disposables,
    );

    this.disposables.push(manager.addChangeHandler(() => this.update()));
    this.update();
  }

  static createOrShow(_extensionUri: vscode.Uri, manager: QuarantineManager): QuarantinePanel {
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

  private async showFailure(detail: string): Promise<void> {
    await vscode.window.showErrorMessage(`FIG: Quarantine operation did not complete. ${detail}`);
  }

  private async canChange(entry?: QuarantinedFile): Promise<boolean> {
    if (this.disposed) return false;
    if (!vscode.workspace.isTrusted) {
      await this.showFailure('A trusted workspace is required.');
      return false;
    }
    if (entry) {
      const normalize = (value: string): string => process.platform === 'win32'
        ? path.resolve(value).toLowerCase() : path.resolve(value);
      if (vscode.workspace.textDocuments.some(document => document.uri.scheme === 'file' &&
          normalize(document.uri.fsPath) === normalize(entry.originalPath) && document.isDirty)) {
        await this.showFailure('The restore destination has unsaved edits. Save or close it before restoring.');
        return false;
      }
      try {
        fs.lstatSync(entry.originalPath);
        await this.showFailure('The restore destination already exists. It will not be overwritten.');
        return false;
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error;
      }
    }
    return true;
  }

  private readEntries(): QuarantinedFile[] {
    const files = this.manager.getQuarantinedFiles();
    const error = this.manager.getStoreError();
    if (error) throw new Error(error);
    return files;
  }

  private async handleMessage(message: unknown): Promise<void> {
    if (this.disposed || this.actionPending || !message || typeof message !== 'object') return;
    const { command, id } = message as { command?: unknown; id?: unknown };
    if (command !== 'restore' && command !== 'delete' && command !== 'clearAll') return;
    if (command !== 'clearAll' && typeof id !== 'string') return;
    this.actionPending = true;
    try {
      if (!await this.canChange()) return;
      // Freeze the exact entries before awaiting native confirmation.
      const files = this.readEntries();
      const selected = command === 'clearAll' ? files : files.filter(entry => entry.id === id);
      if (selected.length === 0) {
        if (command !== 'clearAll') await this.showFailure('The selected entry no longer exists.');
        return;
      }
      const restoring = command === 'restore';
      if (restoring && !selected[0].canRestore) {
        await this.showFailure('This recovery copy cannot be restored.');
        return;
      }
      if (restoring && !await this.canChange(selected[0])) return;
      const action = restoring ? 'Restore file' : command === 'delete' ? 'Delete permanently' : 'Delete selected files';
      const detail = restoring
        ? `${selected[0].originalPath}\nThis restores a potentially unsafe file. Existing files will never be overwritten.`
        : `${selected.length} quarantined file(s):\n${selected.map(entry => entry.originalPath).join('\n')}\nThis permanently deletes the selected recovery copies and cannot be undone.`;
      const answer = await vscode.window.showWarningMessage(
        restoring ? 'Restore this quarantined file?' : 'Permanently delete quarantined files?',
        { modal: true, detail }, action,
      );
      if (answer !== action || !await this.canChange()) return;
      const current = this.readEntries();
      if (selected.some(entry => JSON.stringify(current.find(item => item.id === entry.id)) !== JSON.stringify(entry))) {
        await this.showFailure('The selection changed while confirmation was open. Review the current entries and try again.');
        return;
      }
      let completed = 0;
      for (const entry of selected) {
        if (!await this.canChange(restoring ? entry : undefined)) break;
        const success = restoring ? await this.manager.restore(entry.id, entry) : await this.manager.deletePermanently(entry.id, entry);
        if (!success) {
          await this.showFailure(`${completed} of ${selected.length} completed. ${this.manager.getLastError() || 'Inspect the source and recovery copies before retrying.'}`);
          return;
        }
        completed++;
      }
      if (completed === selected.length) {
        await vscode.window.showInformationMessage(restoring ? 'FIG: File restored.' : `FIG: Permanently deleted ${completed} quarantined file(s).`);
      }
    } catch (error) {
      await this.showFailure(error instanceof Error ? error.message : String(error));
    } finally {
      this.actionPending = false;
      this.update();
    }
  }

  update(): void {
    if (this.disposed) return;
    const files = this.manager.getQuarantinedFiles();
    this.panel.webview.html = this.getHtml(files, this.manager.getStoreError());
  }

  private getHtml(files: QuarantinedFile[], error?: string): string {
    const rows = files.map(f => {
      const threats = f.threats.map(t => `<span class="threat-badge">${this.escapeHtml(t.ruleName)}</span>`).join(' ');
      return `
        <tr data-id="${f.id}">
          <td><code>${this.escapeHtml(f.fileName)}</code></td>
          <td><small>${this.escapeHtml(f.originalPath)}</small></td>
          <td>${threats}</td>
          <td>${new Date(f.detectedAt).toLocaleString()}</td>
          <td>
            <button class="btn restore" ${f.canRestore ? '' : 'disabled'} onclick="restore('${f.id}')">🔄 Restore</button>
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
      <div class="stat-value">${error ? '?' : files.length}</div>
      <div class="stat-label">Quarantined Files</div>
    </div>
    <div class="stat">
      <div class="stat-value">${error ? '?' : files.reduce((sum, f) => sum + f.threats.length, 0)}</div>
      <div class="stat-label">Total Threats</div>
    </div>
  </div>
  ${error ? `<div class="empty">Quarantine unavailable: ${this.escapeHtml(error)}</div>` : files.length > 0 ? `
    <button class="btn clear-all" onclick="clearAll()">🗑️ Clear All Quarantined Files</button>
    <table>
      <thead><tr><th>File</th><th>Original Path</th><th>Threats</th><th>Quarantined</th><th>Actions</th></tr></thead>
      <tbody>${rows}</tbody>
    </table>
  ` : '<div class="empty">✅ No files in quarantine</div>'}
  <script>
    const vscode = acquireVsCodeApi();
    function restore(id) { vscode.postMessage({ command: 'restore', id }); }
    function deleteFile(id) { vscode.postMessage({ command: 'delete', id }); }
    function clearAll() { vscode.postMessage({ command: 'clearAll' }); }
  </script>
</body>
</html>`;
  }

  private escapeHtml(s: string): string {
    return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;');
  }

  dispose(): void {
    if (this.disposed) return;
    this.disposed = true;
    QuarantinePanel.currentPanel = undefined;
    this.panel.dispose();
    for (const d of this.disposables) d.dispose();
  }
}

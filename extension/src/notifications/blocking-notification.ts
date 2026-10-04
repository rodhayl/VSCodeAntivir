import * as vscode from 'vscode';
import * as path from 'path';
import * as fs from 'fs';
import { regularPath } from '../safety/file-change';
import { TaskScanResult, TaskInterceptor } from '../interceptors/task-interceptor';
import { NpmScanResult, NpmScriptInterceptor } from '../interceptors/npm-script-interceptor';
import { GitScanResult, GitConfigInterceptor } from '../interceptors/git-config-interceptor';
import { QuarantineManager } from '../quarantine/quarantine-manager';
import { Threat } from '../scanner/models/threat';
import { Severity } from '../scanner/models/severity';

export interface BlockingNotificationOptions { showModal?: boolean; autoQuarantine?: boolean; }

export class BlockingNotificationService {
  private quarantineManager: QuarantineManager | null = null;
  private taskInterceptor: TaskInterceptor | null = null;
  private npmInterceptor: NpmScriptInterceptor | null = null;
  private gitInterceptor: GitConfigInterceptor | null = null;
  constructor(private outputChannel: vscode.OutputChannel) {}
  setQuarantineManager(value: QuarantineManager): void { this.quarantineManager = value; }
  setTaskInterceptor(value: TaskInterceptor): void { this.taskInterceptor = value; }
  setNpmInterceptor(value: NpmScriptInterceptor): void { this.npmInterceptor = value; }
  setGitInterceptor(value: GitConfigInterceptor): void { this.gitInterceptor = value; }

  private canChange(files: string[]): boolean {
    if (!vscode.workspace.isTrusted) {
      vscode.window.showWarningMessage('FIG: Changes are disabled in Restricted Mode.');
      return false;
    }
    if (vscode.workspace.textDocuments.some(d => files.includes(d.uri.fsPath) && d.isDirty)) {
      vscode.window.showWarningMessage('FIG: Save or revert unsaved edits before applying a file change.');
      return false;
    }
    return true;
  }

  private async reportApplied(applied: boolean, restore: () => Promise<boolean>): Promise<void> {
    if (!applied) {
      vscode.window.showWarningMessage('FIG: No verified complete change. Files may have changed or already be protected. Review the output and any retained backups.');
      return;
    }
    const selection = await vscode.window.showInformationMessage('FIG: Reviewed change applied. The original backup is retained.', 'Undo this change');
    if (selection === 'Undo this change') {
      if (await restore()) vscode.window.showInformationMessage('FIG: Original restored.');
      else vscode.window.showWarningMessage('FIG: Undo refused because the file changed or the backup could not be verified. Your current file was retained.');
    }
  }

  private readContent(filePath: string): Buffer | undefined {
    try { return fs.readFileSync(regularPath(filePath)); } catch { return undefined; }
  }

  private unchanged(filePath: string, reviewedContent: Buffer): boolean {
    if (this.readContent(filePath)?.equals(reviewedContent)) return true;
    vscode.window.showWarningMessage('FIG: File changed during confirmation or since inspection, or cannot be read. Inspect it again before quarantining.');
    return false;
  }

  private async quarantine(filePath: string, threats: Threat[], reviewedContent: Buffer | undefined): Promise<void> {
    if (!this.quarantineManager || !this.canChange([filePath])) return;
    if (!reviewedContent) { vscode.window.showWarningMessage('FIG: Selected file could not be read for review. Inspect it again before quarantining.'); return; }
    if (!this.unchanged(filePath, reviewedContent)) return;
    const choice = await vscode.window.showWarningMessage('Move this file to quarantine?', {
      modal: true, detail: `${filePath}\nThe original will be removed only after a recovery copy and record are saved. This can disrupt the project.`,
    }, 'Quarantine file');
    if (choice !== 'Quarantine file' || !this.canChange([filePath]) || !this.unchanged(filePath, reviewedContent)) return;
    const result = await this.quarantineManager.quarantine(filePath, threats);
    if (result) vscode.window.showInformationMessage('FIG: File quarantined.');
    else vscode.window.showErrorMessage(`FIG: Quarantine did not complete. ${this.quarantineManager.getLastError() || 'Inspect the source and quarantine manager before retrying.'}`);
  }

  async notifyTaskBlocked(result: TaskScanResult): Promise<void> {
    if (!result.hasThreats) return;
    const reviewedContent = result.content === undefined ? this.readContent(result.tasksJsonPath) : Buffer.from(result.content, 'utf8');
    const choice = await vscode.window.showWarningMessage('FIG: Task configuration needs review', {
      modal: true,
      detail: `${result.tasksJsonPath}\n${result.threats.map(t => `${t.taskLabel}: ${t.type}`).join('\n')}\nThese patterns can be legitimate. Disable will remove automatic startup and replace flagged commands/arguments with a harmless echo. No change has been made.`,
    }, 'View file', 'Disable flagged tasks', 'Quarantine file');
    if (choice === 'View file') await vscode.window.showTextDocument(await vscode.workspace.openTextDocument(result.tasksJsonPath));
    else if (choice === 'Quarantine file') await this.quarantine(result.tasksJsonPath, [], reviewedContent);
    else if (choice === 'Disable flagged tasks' && this.taskInterceptor && this.canChange([result.tasksJsonPath])) {
      await this.reportApplied(await this.taskInterceptor.applyBlock(result), async () =>
        this.canChange([result.tasksJsonPath]) && this.taskInterceptor!.restoreOriginal(result.tasksJsonPath));
    }
  }

  async notifyNpmScriptBlocked(result: NpmScanResult): Promise<void> {
    if (!result.hasThreats) return;
    const reviewedContent = result.content === undefined ? this.readContent(result.packageJsonPath) : Buffer.from(result.content, 'utf8');
    const choice = await vscode.window.showWarningMessage('FIG: Package scripts need review', {
      modal: true,
      detail: `${result.packageJsonPath}\n${result.threats.map(t => `${t.scriptName}: ${t.reason}`).join('\n')}\nThese patterns can be legitimate. Disable will add ignore-scripts=true to this package directory’s .npmrc; installation scripts may be required for the project. No change has been made.`,
    }, 'View file', 'Disable lifecycle scripts', 'Quarantine file');
    if (choice === 'View file') await vscode.window.showTextDocument(await vscode.workspace.openTextDocument(result.packageJsonPath));
    else if (choice === 'Quarantine file') await this.quarantine(result.packageJsonPath, [], reviewedContent);
    else if (choice === 'Disable lifecycle scripts' && this.npmInterceptor && this.canChange([result.packageJsonPath, path.join(path.dirname(result.packageJsonPath), '.npmrc')])) {
      await this.reportApplied(await this.npmInterceptor.applyBlock(result), async () =>
        this.canChange([result.packageJsonPath, path.join(path.dirname(result.packageJsonPath), '.npmrc')]) && this.npmInterceptor!.removeBlock(result.packageJsonPath));
    }
  }

  async notifyGitConfigBlocked(result: GitScanResult): Promise<void> {
    if (!result.hasThreats) return;
    const files = [...new Set(result.threats.map(t => t.filePath))];
    const choice = await vscode.window.showWarningMessage('FIG: Git configuration needs review', {
      modal: true,
      detail: `${result.threats.map(t => `${t.filePath}: ${t.configKey}`).join('\n')}\nThese settings and hooks can be legitimate. Disable will comment selected configuration lines and replace flagged hooks with a no-op. Backups will be retained. No change has been made.`,
    }, 'View details', 'Disable reviewed entries');
    if (choice === 'View details') {
      for (const t of result.threats) this.outputChannel.appendLine(`${t.filePath}:${t.line + 1}: ${t.configKey}: ${t.value}`);
      this.outputChannel.show();
    } else if (choice === 'Disable reviewed entries' && this.gitInterceptor && this.canChange(files)) {
      await this.reportApplied(await this.gitInterceptor.applyBlock(result), async () => {
        if (!this.canChange(files)) return false;
        let restored = true;
        for (const file of files) {
          const hook = result.threats.some(t => t.filePath === file && t.type === 'malicious-hook');
          const value = hook ? await this.gitInterceptor!.restoreHook(file) : await this.gitInterceptor!.restoreGitConfig(file);
          restored = value && restored;
        }
        return restored;
      });
    }
  }

  async notifyThreatDetected(filePath: string, threats: Threat[], _options: BlockingNotificationOptions = {}): Promise<void> {
    if (!threats.some(t => t.severity === Severity.CRITICAL)) return;
    const reviewedContent = this.readContent(filePath);
    const choice = await vscode.window.showWarningMessage(`FIG: ${threats.length} finding(s) need review in ${filePath}`, 'View file', 'Quarantine file');
    if (choice === 'View file') await vscode.window.showTextDocument(await vscode.workspace.openTextDocument(filePath));
    else if (choice === 'Quarantine file') await this.quarantine(filePath, threats, reviewedContent);
  }
}

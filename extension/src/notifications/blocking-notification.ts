import * as vscode from 'vscode';
import * as path from 'path';
import { TaskScanResult, TaskThreat } from '../interceptors/task-interceptor';
import { NpmScanResult, NpmScriptThreat } from '../interceptors/npm-script-interceptor';
import { QuarantineManager } from '../quarantine/quarantine-manager';
import { Threat } from '../scanner/models/threat';
import { Severity } from '../scanner/models/severity';

export interface BlockingNotificationOptions {
  showModal?: boolean;
  autoQuarantine?: boolean;
}

export class BlockingNotificationService {
  private outputChannel: vscode.OutputChannel;
  private quarantineManager: QuarantineManager | null = null;

  constructor(outputChannel: vscode.OutputChannel) {
    this.outputChannel = outputChannel;
  }

  setQuarantineManager(manager: QuarantineManager): void {
    this.quarantineManager = manager;
  }

  async notifyTaskBlocked(result: TaskScanResult): Promise<void> {
    const fileName = path.basename(result.tasksJsonPath);
    const criticalThreats = result.threats.filter(t => t.severity === 'critical');
    
    if (criticalThreats.length === 0) {
      return;
    }

    const message = `⚠️ FakeInterviewGuard BLOCKED malicious tasks.json!\n\n` +
      `File: ${fileName}\n` +
      `Threat: Auto-execute on folder open detected.\n\n` +
      `The task configuration was neutralized to prevent automatic code execution.`;

    const selection = await vscode.window.showWarningMessage(
      `🛡️ BLOCKED: Malicious tasks.json neutralized`,
      { modal: true, detail: message },
      'View Details',
      'Quarantine File',
      'Restore Original'
    );

    if (selection === 'View Details') {
      this.showTaskThreatDetails(result);
    } else if (selection === 'Quarantine File' && this.quarantineManager) {
      const threats = this.taskThreatsToThreats(result.threats, result.tasksJsonPath);
      await this.quarantineManager.quarantine(result.tasksJsonPath, threats);
      vscode.window.showInformationMessage('File moved to quarantine');
    } else if (selection === 'Restore Original') {
      vscode.window.showWarningMessage(
        '⚠️ Restoring the original file will re-enable auto-execute. Are you sure?',
        'Yes, restore',
        'Cancel'
      ).then(answer => {
        if (answer === 'Yes, restore') {
          this.outputChannel.appendLine(`[NOTIFICATION] User chose to restore: ${result.tasksJsonPath}`);
        }
      });
    }
  }

  async notifyNpmScriptBlocked(result: NpmScanResult): Promise<void> {
    const fileName = path.basename(result.packageJsonPath);
    
    if (result.threats.length === 0) {
      return;
    }

    const scriptNames = result.threats.map(t => t.scriptName).join(', ');
    
    const message = `⚠️ FakeInterviewGuard BLOCKED malicious npm scripts!\n\n` +
      `File: ${fileName}\n` +
      `Blocked scripts: ${scriptNames}\n\n` +
      `An .npmrc file was created with ignore-scripts=true to prevent execution.`;

    const selection = await vscode.window.showWarningMessage(
      `🛡️ BLOCKED: Malicious npm scripts disabled`,
      { modal: true, detail: message },
      'View Details',
      'Quarantine package.json',
      'Remove Block'
    );

    if (selection === 'View Details') {
      this.showNpmThreatDetails(result);
    } else if (selection === 'Quarantine package.json' && this.quarantineManager) {
      const threats = this.npmThreatsToThreats(result.threats, result.packageJsonPath);
      await this.quarantineManager.quarantine(result.packageJsonPath, threats);
      vscode.window.showInformationMessage('File moved to quarantine');
    }
  }

  async notifyThreatDetected(filePath: string, threats: Threat[], options: BlockingNotificationOptions = {}): Promise<void> {
    const fileName = path.basename(filePath);
    const criticalCount = threats.filter(t => t.severity <= Severity.HIGH).length;
    
    if (criticalCount === 0) {
      return;
    }

    const message = `${criticalCount} high-severity threat${criticalCount !== 1 ? 's' : ''} detected in ${fileName}`;

    if (options.showModal) {
      const selection = await vscode.window.showWarningMessage(
        `🛡️ ${message}`,
        { modal: true },
        'View File',
        'Quarantine',
        'Dismiss'
      );

      if (selection === 'Quarantine' && this.quarantineManager) {
        await this.quarantineManager.quarantine(filePath, threats);
        vscode.window.showInformationMessage('File moved to quarantine');
      } else if (selection === 'View File') {
        const doc = await vscode.workspace.openTextDocument(filePath);
        await vscode.window.showTextDocument(doc);
      }
    } else {
      const selection = await vscode.window.showWarningMessage(
        `🛡️ ${message}`,
        'View',
        'Quarantine',
        'Dismiss'
      );

      if (selection === 'Quarantine' && this.quarantineManager) {
        await this.quarantineManager.quarantine(filePath, threats);
      } else if (selection === 'View') {
        const doc = await vscode.workspace.openTextDocument(filePath);
        await vscode.window.showTextDocument(doc);
      }
    }
  }

  private showTaskThreatDetails(result: TaskScanResult): void {
    this.outputChannel.appendLine('\n=== Malicious Task Configuration Details ===');
    this.outputChannel.appendLine(`File: ${result.tasksJsonPath}`);
    this.outputChannel.appendLine(`Blocked: ${result.blocked ? 'Yes' : 'No'}`);
    this.outputChannel.appendLine('\nThreats:');
    
    for (const threat of result.threats) {
      this.outputChannel.appendLine(`  [${threat.severity.toUpperCase()}] ${threat.type}`);
      this.outputChannel.appendLine(`    Task: ${threat.taskLabel}`);
      this.outputChannel.appendLine(`    Evidence: ${threat.evidence}`);
      this.outputChannel.appendLine(`    Command: ${threat.command.substring(0, 100)}`);
    }
    
    this.outputChannel.appendLine('=========================================\n');
    this.outputChannel.show();
  }

  private showNpmThreatDetails(result: NpmScanResult): void {
    this.outputChannel.appendLine('\n=== Malicious npm Script Details ===');
    this.outputChannel.appendLine(`File: ${result.packageJsonPath}`);
    this.outputChannel.appendLine(`Scripts Blocked: ${result.npmrcModified ? 'Yes' : 'No'}`);
    this.outputChannel.appendLine('\nThreats:');
    
    for (const threat of result.threats) {
      this.outputChannel.appendLine(`  [${threat.severity.toUpperCase()}] ${threat.scriptName}`);
      this.outputChannel.appendLine(`    Reason: ${threat.reason}`);
      this.outputChannel.appendLine(`    Command: ${threat.scriptCommand.substring(0, 100)}`);
    }
    
    this.outputChannel.appendLine('=====================================\n');
    this.outputChannel.show();
  }

  private taskThreatsToThreats(taskThreats: TaskThreat[], filePath: string): Threat[] {
    return taskThreats.map((t, idx) => ({
      id: `task-${t.type}-${idx}`,
      ruleId: `interceptor-task-${t.type}`,
      ruleName: `Task ${t.type.replace('-', ' ')}`,
      severity: t.severity === 'critical' ? Severity.CRITICAL : t.severity === 'high' ? Severity.HIGH : Severity.MEDIUM,
      confidence: 'high',
      message: `Task "${t.taskLabel}": ${t.evidence}`,
      filePath,
      location: { startLine: t.line, startCol: 0, endLine: t.line, endCol: 100 },
      matchedStrings: [t.evidence],
    }));
  }

  private npmThreatsToThreats(npmThreats: NpmScriptThreat[], filePath: string): Threat[] {
    return npmThreats.map((t, idx) => ({
      id: `npm-${t.scriptName}-${idx}`,
      ruleId: `interceptor-npm-${t.scriptName}`,
      ruleName: `Malicious ${t.scriptName} script`,
      severity: t.severity === 'critical' ? Severity.CRITICAL : t.severity === 'high' ? Severity.HIGH : Severity.MEDIUM,
      confidence: 'high',
      message: `${t.reason}: ${t.scriptCommand.substring(0, 80)}`,
      filePath,
      location: { startLine: t.line, startCol: 0, endLine: t.line, endCol: 100 },
      matchedStrings: [t.scriptCommand],
    }));
  }
}

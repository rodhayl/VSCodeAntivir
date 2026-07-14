import * as vscode from 'vscode';
import * as path from 'path';
import { TaskScanResult, TaskThreat, TaskInterceptor } from '../interceptors/task-interceptor';
import { NpmScanResult, NpmScriptThreat, NpmScriptInterceptor } from '../interceptors/npm-script-interceptor';
import { GitScanResult, GitConfigThreat, GitConfigInterceptor } from '../interceptors/git-config-interceptor';
import { QuarantineManager } from '../quarantine/quarantine-manager';
import { Threat } from '../scanner/models/threat';
import { Severity, stringToSeverity } from '../scanner/models/severity';

export interface BlockingNotificationOptions {
  showModal?: boolean;
  autoQuarantine?: boolean;
}

export class BlockingNotificationService {
  private outputChannel: vscode.OutputChannel;
  private quarantineManager: QuarantineManager | null = null;
  private taskInterceptor: TaskInterceptor | null = null;
  private npmInterceptor: NpmScriptInterceptor | null = null;
  private gitInterceptor: GitConfigInterceptor | null = null;

  constructor(outputChannel: vscode.OutputChannel) {
    this.outputChannel = outputChannel;
  }

  setQuarantineManager(manager: QuarantineManager): void {
    this.quarantineManager = manager;
  }

  setTaskInterceptor(interceptor: TaskInterceptor): void {
    this.taskInterceptor = interceptor;
  }

  setNpmInterceptor(interceptor: NpmScriptInterceptor): void {
    this.npmInterceptor = interceptor;
  }

  setGitInterceptor(interceptor: GitConfigInterceptor): void {
    this.gitInterceptor = interceptor;
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
      ).then(async answer => {
        if (answer === 'Yes, restore') {
          if (this.taskInterceptor) {
            const restored = await this.taskInterceptor.restoreOriginal(result.tasksJsonPath);
            if (restored) {
              vscode.window.showInformationMessage('Original tasks.json restored');
            } else {
              vscode.window.showErrorMessage('Failed to restore tasks.json');
            }
          }
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
    } else if (selection === 'Remove Block') {
      vscode.window.showWarningMessage(
        '⚠️ Removing the block will re-enable npm script execution. Are you sure?',
        'Yes, remove',
        'Cancel'
      ).then(async answer => {
        if (answer === 'Yes, remove') {
          if (this.npmInterceptor) {
            const removed = await this.npmInterceptor.removeBlock(result.packageJsonPath);
            if (removed) {
              vscode.window.showInformationMessage('npm block removed');
            } else {
              vscode.window.showErrorMessage('Failed to remove npm block');
            }
          }
        }
      });
    }
  }

  async notifyThreatDetected(filePath: string, threats: Threat[], options: BlockingNotificationOptions = {}): Promise<void> {
    const fileName = path.basename(filePath);
    const severeCount = threats.filter(t => t.severity === Severity.CRITICAL).length;

    if (severeCount === 0) {
      return;
    }

    const message = `${severeCount} critical threat${severeCount !== 1 ? 's' : ''} detected in ${fileName}`;

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
      severity: stringToSeverity(t.severity),
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
      severity: stringToSeverity(t.severity),
      confidence: 'high',
      message: `${t.reason}: ${t.scriptCommand.substring(0, 80)}`,
      filePath,
      location: { startLine: t.line, startCol: 0, endLine: t.line, endCol: 100 },
      matchedStrings: [t.scriptCommand],
    }));
  }

  async notifyGitConfigBlocked(result: GitScanResult): Promise<void> {
    if (result.threats.length === 0) {
      return;
    }

    const threatTypes = [...new Set(result.threats.map(t => t.type))];
    const firstThreat = result.threats[0];
    const configPath = firstThreat.filePath;
    
    let threatDescription = '';
    if (threatTypes.includes('fsmonitor')) {
      threatDescription = 'core.fsmonitor exploit (arbitrary code execution)';
    } else if (threatTypes.includes('hookspath')) {
      threatDescription = 'custom hooks path (redirected git hooks)';
    } else if (threatTypes.includes('malicious-hook')) {
      threatDescription = 'malicious git hook scripts detected';
    } else {
      threatDescription = threatTypes.join(', ');
    }

    const message = `⚠️ FakeInterviewGuard BLOCKED dangerous git configuration!\n\n` +
      `Config: ${configPath}\n` +
      `Threat: ${threatDescription}\n\n` +
      `This exploit technique was used in the March 2026 Emacs/Vim RCE attacks.\n` +
      `The dangerous configuration has been commented out to prevent execution.`;

    const selection = await vscode.window.showWarningMessage(
      `🛡️ BLOCKED: Dangerous git config neutralized`,
      { modal: true, detail: message },
      'View Details',
      'Quarantine .git/config',
      'Restore Original'
    );

    if (selection === 'View Details') {
      this.showGitThreatDetails(result);
    } else if (selection === 'Quarantine .git/config' && this.quarantineManager) {
      const threats = this.gitThreatsToThreats(result.threats, configPath);
      await this.quarantineManager.quarantine(configPath, threats);
      vscode.window.showInformationMessage('Git config moved to quarantine');
    } else if (selection === 'Restore Original') {
      vscode.window.showWarningMessage(
        '⚠️ Restoring the original config will re-enable code execution. Are you sure?',
        'Yes, restore',
        'Cancel'
      ).then(async answer => {
        if (answer === 'Yes, restore') {
          if (this.gitInterceptor) {
            const restored = await this.gitInterceptor.restoreGitConfig(configPath);
            if (restored) {
              vscode.window.showInformationMessage('Git config restored from backup');
            } else {
              vscode.window.showErrorMessage('Failed to restore git config');
            }
          }
        }
      });
    }
  }

  private showGitThreatDetails(result: GitScanResult): void {
    this.outputChannel.appendLine('\n=== Dangerous Git Configuration Details ===');
    this.outputChannel.appendLine(`Blocked: ${result.blocked ? 'Yes' : 'No'}`);
    this.outputChannel.appendLine('\nThreats:');
    
    for (const threat of result.threats) {
      this.outputChannel.appendLine(`  [${threat.severity.toUpperCase()}] ${threat.type}`);
      this.outputChannel.appendLine(`    File: ${threat.filePath}`);
      this.outputChannel.appendLine(`    Line: ${threat.line}`);
      this.outputChannel.appendLine(`    Config: ${threat.configKey} = ${threat.value.substring(0, 100)}`);
    }
    
    this.outputChannel.appendLine('\nThis attack vector was used in March 2026 by:');
    this.outputChannel.appendLine('  - Emacs/Vim RCE attacks via core.fsmonitor');
    this.outputChannel.appendLine('  - Lazarus/BlueNoroff supply chain attacks');
    this.outputChannel.appendLine('==========================================\n');
    this.outputChannel.show();
  }

  private gitThreatsToThreats(gitThreats: GitConfigThreat[], filePath: string): Threat[] {
    return gitThreats.map((t, idx) => ({
      id: `git-${t.type}-${idx}`,
      ruleId: `interceptor-git-${t.type}`,
      ruleName: `Git ${t.type} exploit`,
      severity: stringToSeverity(t.severity),
      confidence: 'high',
      message: `${t.configKey}: ${t.value.substring(0, 80)}`,
      filePath,
      location: { startLine: t.line, startCol: 0, endLine: t.line, endCol: 100 },
      matchedStrings: [t.value],
    }));
  }
}

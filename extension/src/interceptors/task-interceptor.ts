import * as vscode from 'vscode';
import * as fs from 'fs';
import * as path from 'path';

export interface TaskThreat {
  type: 'auto-execute' | 'dangerous-command' | 'url-shortener' | 'piped-exec';
  severity: 'critical' | 'high' | 'medium';
  taskLabel: string;
  command: string;
  evidence: string;
  line: number;
}

export interface TaskScanResult {
  hasThreats: boolean;
  threats: TaskThreat[];
  tasksJsonPath: string;
  blocked: boolean;
}

const DANGEROUS_PATTERNS = [
  { pattern: /\bcurl\s+/i, type: 'dangerous-command' as const, severity: 'high' as const },
  { pattern: /\bwget\s+/i, type: 'dangerous-command' as const, severity: 'high' as const },
  { pattern: /\bInvoke-WebRequest\b/i, type: 'dangerous-command' as const, severity: 'high' as const },
  { pattern: /\bInvoke-Expression\b/i, type: 'dangerous-command' as const, severity: 'critical' as const },
  { pattern: /\|\s*(sh|bash|cmd|powershell)\b/i, type: 'piped-exec' as const, severity: 'critical' as const },
];

const URL_SHORTENERS = ['bit.ly', 'short.gy', 'tinyurl.com', 'is.gd', 't.co', 'rb.gy', 'goo.gl'];

export class TaskInterceptor {
  private outputChannel: vscode.OutputChannel;
  private blockedPaths = new Set<string>();
  private onThreatDetected: ((result: TaskScanResult) => void) | null = null;

  constructor(outputChannel: vscode.OutputChannel) {
    this.outputChannel = outputChannel;
  }

  setThreatHandler(handler: (result: TaskScanResult) => void): void {
    this.onThreatDetected = handler;
  }

  async interceptWorkspace(workspaceFolder: vscode.WorkspaceFolder): Promise<TaskScanResult | null> {
    const tasksJsonPath = path.join(workspaceFolder.uri.fsPath, '.vscode', 'tasks.json');
    
    if (!fs.existsSync(tasksJsonPath)) {
      return null;
    }

    return this.scanAndBlock(tasksJsonPath);
  }

  async scanAndBlock(tasksJsonPath: string): Promise<TaskScanResult> {
    const result: TaskScanResult = {
      hasThreats: false,
      threats: [],
      tasksJsonPath,
      blocked: false,
    };

    let content: string;
    try {
      content = fs.readFileSync(tasksJsonPath, 'utf-8');
    } catch {
      return result;
    }

    let tasks: any;
    try {
      tasks = JSON.parse(content);
    } catch {
      return result;
    }

    const taskList = tasks.tasks || [];
    const lines = content.split('\n');

    for (const task of taskList) {
      const taskLabel = task.label || 'unnamed';
      const command = task.command || '';
      const args = (task.args || []).join(' ');
      const fullCommand = `${command} ${args}`.trim();

      // Check for auto-execute on folder open (CRITICAL)
      if (task.runOptions?.runOn === 'folderOpen') {
        const lineNum = this.findLineNumber(lines, 'folderOpen');
        result.threats.push({
          type: 'auto-execute',
          severity: 'critical',
          taskLabel,
          command: fullCommand,
          evidence: '"runOn": "folderOpen"',
          line: lineNum,
        });
      }

      // Check dangerous command patterns
      for (const dp of DANGEROUS_PATTERNS) {
        if (dp.pattern.test(fullCommand)) {
          const lineNum = this.findLineNumber(lines, command.substring(0, 20));
          result.threats.push({
            type: dp.type,
            severity: dp.severity,
            taskLabel,
            command: fullCommand.substring(0, 200),
            evidence: fullCommand.match(dp.pattern)?.[0] || '',
            line: lineNum,
          });
        }
      }

      // Check URL shorteners
      for (const shortener of URL_SHORTENERS) {
        if (fullCommand.toLowerCase().includes(shortener)) {
          const lineNum = this.findLineNumber(lines, shortener);
          result.threats.push({
            type: 'url-shortener',
            severity: 'high',
            taskLabel,
            command: fullCommand.substring(0, 200),
            evidence: shortener,
            line: lineNum,
          });
        }
      }
    }

    result.hasThreats = result.threats.length > 0;

    if (result.hasThreats) {
      const hasCritical = result.threats.some(t => t.severity === 'critical');
      
      if (hasCritical) {
        result.blocked = await this.blockTasks(tasksJsonPath, content, result.threats);
        
        if (result.blocked) {
          this.outputChannel.appendLine(`[BLOCKED] Neutralized malicious tasks.json: ${tasksJsonPath}`);
          this.blockedPaths.add(tasksJsonPath);
        }
      }

      if (this.onThreatDetected) {
        this.onThreatDetected(result);
      }
    }

    return result;
  }

  private async blockTasks(filePath: string, content: string, threats: TaskThreat[]): Promise<boolean> {
    try {
      let neutralized = content;

      // Neutralize auto-execute (folderOpen → default)
      if (threats.some(t => t.type === 'auto-execute')) {
        neutralized = neutralized.replace(/"folderOpen"/g, '"default" /* BLOCKED by FakeInterviewGuard */');
      }

      // Neutralize piped shell execution (curl ... | sh → echo blocked)
      if (threats.some(t => t.type === 'piped-exec')) {
        neutralized = neutralized.replace(/("command"\s*:\s*"[^"]*\|\s*(?:sh|bash|cmd|powershell)[^"]*")/g,
          '"command": "echo BLOCKED by FakeInterviewGuard — piped execution removed" /* $1 */');
      }

      // Neutralize dangerous commands (curl/wget/Invoke-Expression)
      if (threats.some(t => t.type === 'dangerous-command')) {
        neutralized = neutralized.replace(/("command"\s*:\s*"(curl|wget|Invoke-WebRequest|Invoke-Expression)[^"]*")/g,
          '"command": "echo BLOCKED by FakeInterviewGuard — dangerous command removed" /* $1 */');
      }

      // Neutralize URL shorteners
      if (threats.some(t => t.type === 'url-shortener')) {
        const shorteners = ['bit\\.ly', 'short\\.gy', 'tinyurl\\.com', 'is\\.gd', 't\\.co', 'rb\\.gy', 'goo\\.gl'];
        for (const s of shorteners) {
          neutralized = neutralized.replace(new RegExp(`("${s}[^"]*")`, 'g'),
            '"BLOCKED_URL" /* $1 */');
        }
      }

      // Create backup
      const backupPath = filePath + '.fig-backup';
      if (!fs.existsSync(backupPath)) {
        fs.writeFileSync(backupPath, content, 'utf-8');
      }

      // Write neutralized version
      fs.writeFileSync(filePath, neutralized, 'utf-8');

      const blockedTypes = [...new Set(threats.map(t => t.type))].join(', ');
      this.outputChannel.appendLine(`[TASK-INTERCEPTOR] Blocked threats (${blockedTypes}) in ${filePath}`);
      this.outputChannel.appendLine(`[TASK-INTERCEPTOR] Original backed up to ${backupPath}`);

      return true;
    } catch (e: any) {
      this.outputChannel.appendLine(`[TASK-INTERCEPTOR] Failed to block: ${e.message}`);
      return false;
    }
  }

  private findLineNumber(lines: string[], search: string): number {
    for (let i = 0; i < lines.length; i++) {
      if (lines[i].includes(search)) {
        return i;
      }
    }
    return 0;
  }

  isBlocked(filePath: string): boolean {
    return this.blockedPaths.has(filePath);
  }

  async restoreOriginal(tasksJsonPath: string): Promise<boolean> {
    const backupPath = tasksJsonPath + '.fig-backup';
    
    if (!fs.existsSync(backupPath)) {
      return false;
    }

    try {
      const original = fs.readFileSync(backupPath, 'utf-8');
      fs.writeFileSync(tasksJsonPath, original, 'utf-8');
      fs.unlinkSync(backupPath);
      this.blockedPaths.delete(tasksJsonPath);
      this.outputChannel.appendLine(`[TASK-INTERCEPTOR] Restored original: ${tasksJsonPath}`);
      return true;
    } catch {
      return false;
    }
  }
}

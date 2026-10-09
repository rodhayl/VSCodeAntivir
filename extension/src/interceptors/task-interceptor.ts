import * as vscode from 'vscode';
import * as fs from 'fs';
import * as path from 'path';
import { parse, modify, applyEdits, ParseError } from 'jsonc-parser';
import { FileChange, readForReview } from '../safety/file-change';

export interface TaskThreat {
  type: 'auto-execute' | 'dangerous-command' | 'url-shortener' | 'piped-exec';
  severity: 'critical' | 'high' | 'medium';
  taskLabel: string;
  taskIndex: number;
  command: string;
  evidence: string;
  line: number;
}

export interface TaskScanResult {
  hasThreats: boolean;
  threats: TaskThreat[];
  tasksJsonPath: string;
  blocked: boolean;
  content?: string;
  error?: string;
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
  private changes = new FileChange();
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

  async scanAndBlock(tasksJsonPath: string, notify = true): Promise<TaskScanResult> {
    const result: TaskScanResult = {
      hasThreats: false,
      threats: [],
      tasksJsonPath,
      blocked: false,
    };

    let content: string;
    try {
      content = readForReview(tasksJsonPath);
      result.content = content;
    } catch (error) {
      result.error = String(error);
      return result;
    }

    let tasks: { tasks?: { label?: string; command?: unknown; args?: unknown[]; runOptions?: { runOn?: string } }[] };
    try {
      const errors: ParseError[] = [];
      tasks = parse(content, errors, { allowTrailingComma: true });
      if (errors.length || !tasks || typeof tasks !== 'object' || Array.isArray(tasks) ||
          (tasks.tasks !== undefined && (!Array.isArray(tasks.tasks) || tasks.tasks.some((task: unknown) => !task || typeof task !== 'object' || Array.isArray(task))))) throw new Error('Invalid task configuration');
    } catch (error) {
      result.error = String(error);
      return result;
    }

    const taskList = tasks.tasks || [];
    const lines = content.split('\n');

    for (const [taskIndex, task] of taskList.entries()) {
      if (!task || typeof task !== 'object') continue;
      const taskLabel = task.label || 'unnamed';
      const command = typeof task.command === 'string' ? task.command : '';
      const args = (Array.isArray(task.args) ? task.args : [task.args || '']).join(' ');
      const fullCommand = `${command} ${args}`.trim();

      // Check for auto-execute on folder open (CRITICAL)
      if (task.runOptions?.runOn === 'folderOpen') {
        const lineNum = this.findLineNumber(lines, 'folderOpen');
        result.threats.push({
          type: 'auto-execute',
          severity: 'critical',
          taskLabel,
          taskIndex,
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
            taskIndex,
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
            taskIndex,
            command: fullCommand.substring(0, 200),
            evidence: shortener,
            line: lineNum,
          });
        }
      }
    }

    result.hasThreats = result.threats.length > 0;

    if (result.hasThreats && notify && this.onThreatDetected) this.onThreatDetected(result);
    return result;
  }

  async applyBlock(review: TaskScanResult): Promise<boolean> {
    if (review.content === undefined || !review.hasThreats) return false;
    try {
      let updated = review.content;
      const byTask = new Map<number, TaskThreat[]>();
      for (const threat of review.threats) byTask.set(threat.taskIndex, [...(byTask.get(threat.taskIndex) || []), threat]);
      for (const [index, threats] of byTask) {
        const edit = (keys: (string | number)[], value: unknown) => {
          updated = applyEdits(updated, modify(updated, keys, value, { formattingOptions: { insertSpaces: true, tabSize: 2 } }));
        };
        if (threats.some(t => t.type === 'auto-execute')) edit(['tasks', index, 'runOptions', 'runOn'], 'default');
        if (threats.some(t => t.type !== 'auto-execute')) {
          edit(['tasks', index, 'command'], 'echo Task disabled after review by FakeInterviewGuard');
          edit(['tasks', index, 'args'], []);
        }
      }
      const applied = this.changes.apply(review.tasksJsonPath, review.content, updated);
      if (!applied) return false;
      const verified = await this.scanAndBlock(review.tasksJsonPath, false);
      if (verified.error || verified.hasThreats) return false;
      this.blockedPaths.add(review.tasksJsonPath);
      return true;
    } catch (error) {
      this.outputChannel.appendLine(`[TASK-INTERCEPTOR] Change refused: ${String(error)}`);
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
    try {
      const restored = this.changes.restore(tasksJsonPath);
      if (restored) this.blockedPaths.delete(tasksJsonPath);
      return restored;
    } catch { return false; }
  }
}

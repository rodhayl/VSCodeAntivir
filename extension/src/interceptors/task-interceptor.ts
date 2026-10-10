import * as vscode from 'vscode';
import * as fs from 'fs';
import * as path from 'path';
import { modify, applyEdits } from 'jsonc-parser';
import { parseTaskConfiguration, taskVariants, taskRemediationError, taskAt, TASK_PLATFORMS, TaskConfiguration } from './task-configuration';
import { FileChange, readForReview } from '../safety/file-change';

export interface TaskThreat {
  type: 'auto-execute' | 'dangerous-command' | 'url-shortener' | 'piped-exec';
  severity: 'critical' | 'high' | 'medium';
  taskLabel: string;
  taskIndex: number;
  taskPath?: (string | number)[];
  variant?: string;
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
  remediationError?: string;
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

    let tasks: TaskConfiguration;
    try { tasks = parseTaskConfiguration(content); }
    catch (error) { result.error = String(error); return result; }
    const lines = content.split('\n');
    for (const task of taskVariants(tasks)) {
      const { taskLabel, taskIndex, taskPath, variant, command, fullCommand } = task;

      // Check for auto-execute on folder open (CRITICAL)
      if (task.autoExecute) {
        const lineNum = this.findLineNumber(lines, 'folderOpen');
        result.threats.push({
          type: 'auto-execute',
          severity: 'critical',
          taskLabel,
          taskIndex,
          taskPath,
          variant,
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
            taskPath,
            variant,
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
            taskPath,
            variant,
            command: fullCommand.substring(0, 200),
            evidence: shortener,
            line: lineNum,
          });
        }
      }
    }

    result.hasThreats = result.threats.length > 0;
    if (result.hasThreats) result.remediationError = taskRemediationError(tasks, result.threats.map(threat => threat.taskPath!));

    if (result.hasThreats && notify && this.onThreatDetected) this.onThreatDetected(result);
    return result;
  }

  async applyBlock(review: TaskScanResult): Promise<boolean> {
    if (review.content === undefined || !review.hasThreats) return false;
    try {
      const configuration = parseTaskConfiguration(review.content);
      // Recompute the supported scope from the reviewed bytes; never rely on a
      // missing UI flag or on incomplete caller-supplied variant metadata.
      const fresh = await this.scanAndBlock(review.tasksJsonPath, false);
      if (fresh.content !== review.content || fresh.error || !fresh.hasThreats) return false;
      if (fresh.remediationError) throw new Error(fresh.remediationError);
      let updated = review.content;
      const byTask = new Map<string, TaskThreat[]>();
      for (const threat of fresh.threats) {
        const key = JSON.stringify(threat.taskPath);
        byTask.set(key, [...(byTask.get(key) || []), threat]);
      }
      for (const threats of byTask.values()) {
        const taskPath = threats[0].taskPath!;
        const task = taskAt(configuration, taskPath);
        const edit = (keys: (string | number)[], value: unknown) => {
          updated = applyEdits(updated, modify(updated, keys, value, { formattingOptions: { insertSpaces: true, tabSize: 2 } }));
        };
        const paths = [taskPath, ...TASK_PLATFORMS.filter(platform => task[platform] !== undefined).map(platform => [...taskPath, platform])];
        for (const variantPath of paths) {
          edit([...variantPath, 'runOptions', 'runOn'], 'default');
          if (threats.some(threat => threat.type !== 'auto-execute')) {
            edit([...variantPath, 'type'], 'shell');
            edit([...variantPath, 'command'], 'echo Task disabled after review by FakeInterviewGuard');
            edit([...variantPath, 'args'], []);
            edit([...variantPath, 'dependsOn'], []);
          }
        }
      }
      // Verify the resulting declarations, not only the same pattern detector.
      const candidate = parseTaskConfiguration(updated);
      for (const threats of byTask.values()) {
        const taskPath = threats[0].taskPath!;
        const neutralized = threats.some(threat => threat.type !== 'auto-execute');
        const variants = taskVariants(candidate).filter(variant => JSON.stringify(variant.taskPath) === JSON.stringify(taskPath));
        if (variants.some(variant => variant.autoExecute || (neutralized && variant.fullCommand !== 'echo Task disabled after review by FakeInterviewGuard'))) return false;
        if (neutralized) {
          const task = taskAt(candidate, taskPath);
          for (const value of [task, ...TASK_PLATFORMS.filter(platform => task[platform] !== undefined).map(platform => taskAt(task, [platform]))]) {
            if (!Array.isArray(value.dependsOn) || value.dependsOn.length !== 0) return false;
          }
        }
      }
      const applied = this.changes.apply(review.tasksJsonPath, review.content, updated);
      if (!applied) return false;
      const verified = await this.scanAndBlock(review.tasksJsonPath, false);
      if (verified.content !== updated || verified.error || verified.hasThreats) return false;
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

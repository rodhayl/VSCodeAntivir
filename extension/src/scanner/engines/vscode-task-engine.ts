import * as path from 'path';
import { parse, ParseError } from 'jsonc-parser';
import { Threat, ThreatLocation } from '../models/threat';
import { Severity } from '../models/severity';

function loc(line: number, col: number, endCol?: number): ThreatLocation {
  return { startLine: line, startCol: col, endLine: line, endCol: endCol || col + 10 };
}

function findLine(content: string, search: string): number {
  const lines = content.split('\n');
  for (let i = 0; i < lines.length; i++) {
    if (lines[i].includes(search)) return i;
  }
  return 0;
}

export function runVscodeTaskEngine(content: string, filePath: string): Threat[] {
  const threats: Threat[] = [];
  const fileName = path.basename(filePath);
  if (fileName !== 'tasks.json') return threats;

  let tasks: { tasks?: { label?: string; command?: unknown; args?: unknown[]; runOptions?: { runOn?: string } }[] };
  try {
    const errors: ParseError[] = [];
    tasks = parse(content, errors, { allowTrailingComma: true });
    if (errors.length || !tasks || typeof tasks !== 'object' || Array.isArray(tasks) ||
          (tasks.tasks !== undefined && (!Array.isArray(tasks.tasks) || tasks.tasks.some((task: unknown) => !task || typeof task !== 'object' || Array.isArray(task))))) return threats;
  } catch {
    return threats;
  }

  const taskList = tasks.tasks || [];
  for (const task of taskList) {
    if (!task || typeof task !== 'object') continue;
    // 1. Auto-execute on folder open
    if (task.runOptions?.runOn === 'folderOpen') {
      const line = findLine(content, 'folderOpen');
      threats.push({
        id: `vscode-task-autoexec-${Date.now()}`,
        ruleId: 'vscode-task-autoexec',
        ruleName: 'VS Code Task Auto-Execute on Open',
        severity: Severity.CRITICAL,
        confidence: 'high',
        message: 'Task is configured to auto-execute when the workspace is opened — this is a known Contagious Interview attack vector',
        filePath,
        location: loc(line, 0),
        mitre: { tactic: 'Execution', technique: 'T1204.002', name: 'Malicious File' },
        matchedStrings: ['runOn: folderOpen'],
        remediation: {
          message: 'Remove the "runOn": "folderOpen" property from the task configuration',
          actions: ['neutralize'],
        },
      });
    }

    // 2. Shell commands with curl/wget
    const command = typeof task.command === 'string' ? task.command : '';
    const args = (Array.isArray(task.args) ? task.args : []).join(' ');
    const fullCommand = `${command} ${args}`.toLowerCase();

    const dangerousPatterns = [
      { pattern: 'curl ', reason: 'curl command in task' },
      { pattern: 'wget ', reason: 'wget command in task' },
      { pattern: 'invoke-webrequest', reason: 'PowerShell web request in task' },
      { pattern: 'invoke-expression', reason: 'PowerShell expression evaluation in task' },
      { pattern: '--install-extension', reason: 'IDE extension installation command in task' },
      { pattern: '-encodedcommand', reason: 'PowerShell encoded command in task' },
      { pattern: 'frombase64string', reason: 'base64-decoding launcher in task' },
      { pattern: 'graph.microsoft.com', reason: 'Microsoft Graph used as remote task endpoint' },
      { pattern: 'sharepoint.com', reason: 'SharePoint used as remote task endpoint' },
    ];

    for (const dp of dangerousPatterns) {
      if (fullCommand.includes(dp.pattern)) {
        const line = findLine(content, command);
        threats.push({
          id: `vscode-task-dangerous-cmd-${Date.now()}-${dp.pattern.trim()}`,
          ruleId: 'vscode-task-dangerous-cmd',
          ruleName: 'Dangerous Command in VS Code Task',
          severity: Severity.HIGH,
          confidence: 'high',
          message: `Task contains ${dp.reason}: "${command.substring(0, 80)}"`,
          filePath,
          location: loc(line, 0),
          mitre: { tactic: 'Execution', technique: 'T1059', name: 'Command and Scripting Interpreter' },
          matchedStrings: [command],
        });
      }
    }

    // 3. Piped execution
    if (/\|\s*(sh|bash|cmd|powershell)\b/i.test(fullCommand)) {
      const line = findLine(content, '|');
      threats.push({
        id: `vscode-task-piped-exec-${Date.now()}`,
        ruleId: 'vscode-task-piped-exec',
        ruleName: 'Piped Shell Execution in Task',
        severity: Severity.CRITICAL,
        confidence: 'high',
        message: 'Task pipes downloaded content to a shell — classic download-and-execute pattern',
        filePath,
        location: loc(line, 0),
        matchedStrings: [fullCommand.substring(0, 100)],
      });
    }

    // 4. URL shorteners
    const shorteners = ['bit.ly', 'short.gy', 't.co', 'tinyurl.com', 'is.gd', 'rb.gy'];
    for (const shortener of shorteners) {
      if (fullCommand.includes(shortener)) {
        const line = findLine(content, shortener);
        threats.push({
          id: `vscode-task-shortener-${Date.now()}`,
          ruleId: 'vscode-task-shortener',
          ruleName: 'URL Shortener in Task Command',
          severity: Severity.HIGH,
          confidence: 'medium',
          message: `Task references URL shortener "${shortener}" — used to hide malicious payload URLs`,
          filePath,
          location: loc(line, 0),
          matchedStrings: [shortener],
        });
      }
    }
  }

  return threats;
}

import * as vscode from 'vscode';
import * as fs from 'fs';
import * as path from 'path';
import { FileChange, readForReview } from '../safety/file-change';

export interface NpmScriptThreat {
  scriptName: string;
  scriptCommand: string;
  severity: 'critical' | 'high' | 'medium';
  reason: string;
  line: number;
}

export interface NpmScanResult {
  hasThreats: boolean;
  threats: NpmScriptThreat[];
  packageJsonPath: string;
  blocked: boolean;
  npmrcModified: boolean;
  content?: string;
  npmrcContent?: string;
  error?: string;
}

const DANGEROUS_SCRIPTS = ['preinstall', 'postinstall', 'prestart', 'prepare'];

const DANGEROUS_INDICATORS = [
  { pattern: /\bnode\s+\S+\.js/i, reason: 'Executes external JS file' },
  { pattern: /\bcurl\s+/i, reason: 'Network download in install script' },
  { pattern: /\bwget\s+/i, reason: 'Network download in install script' },
  { pattern: /\beval\b/i, reason: 'Dynamic code execution' },
  { pattern: /child_process|execSync|execFile/i, reason: 'Shell command execution' },

  { pattern: /\bsh\s+-c\b/i, reason: 'Shell command execution' },
  { pattern: /\bbash\s+-c\b/i, reason: 'Shell command execution' },
  { pattern: /\bpowershell\b/i, reason: 'PowerShell execution' },
  { pattern: /\bcmd\s+\/c\b/i, reason: 'CMD execution' },
  { pattern: /setup_bun|bun_environment/i, reason: 'Known Contagious Interview pattern' },
];

export class NpmScriptInterceptor {
  private outputChannel: vscode.OutputChannel;
  private blockedPackages = new Set<string>();
  private changes = new FileChange();
  private onThreatDetected: ((result: NpmScanResult) => void) | null = null;

  constructor(outputChannel: vscode.OutputChannel) {
    this.outputChannel = outputChannel;
  }

  setThreatHandler(handler: (result: NpmScanResult) => void): void {
    this.onThreatDetected = handler;
  }

  async interceptWorkspace(workspaceFolder: vscode.WorkspaceFolder): Promise<NpmScanResult | null> {
    const packageJsonPath = path.join(workspaceFolder.uri.fsPath, 'package.json');
    
    if (!fs.existsSync(packageJsonPath)) {
      return null;
    }

    return this.scanAndBlock(packageJsonPath);
  }

  async scanAndBlock(packageJsonPath: string): Promise<NpmScanResult> {
    const result: NpmScanResult = {
      hasThreats: false,
      threats: [],
      packageJsonPath,
      blocked: false,
      npmrcModified: false,
    };

    let content: string;
    try {
      content = readForReview(packageJsonPath);
      result.content = content;
      const npmrc = path.join(path.dirname(packageJsonPath), '.npmrc');
      if (fs.existsSync(npmrc)) result.npmrcContent = readForReview(npmrc);
    } catch (error) {
      result.error = String(error);
      return result;
    }

    let pkg: any;
    try {
      pkg = JSON.parse(content);
    } catch (error) {
      result.error = String(error);
      return result;
    }

    const scripts = pkg.scripts || {};
    const lines = content.split('\n');

    for (const scriptName of DANGEROUS_SCRIPTS) {
      const scriptCommand = scripts[scriptName];
      if (typeof scriptCommand !== 'string' || !scriptCommand) continue;

      for (const indicator of DANGEROUS_INDICATORS) {
        if (indicator.pattern.test(scriptCommand)) {
          const lineNum = this.findLineNumber(lines, scriptName);
          result.threats.push({
            scriptName,
            scriptCommand: scriptCommand.substring(0, 200),
            severity: (scriptName === 'preinstall' || scriptName === 'prepare') ? 'critical' : 'high',
            reason: indicator.reason,
            line: lineNum,
          });
          break;
        }
      }
    }

    result.hasThreats = result.threats.length > 0;

    if (result.hasThreats && this.onThreatDetected) this.onThreatDetected(result);
    return result;
  }

  async applyBlock(review: NpmScanResult): Promise<boolean> {
    try {
      if (review.content === undefined || readForReview(review.packageJsonPath) !== review.content) return false;
      const npmrc = path.join(path.dirname(review.packageJsonPath), '.npmrc');
      const original = review.npmrcContent;
      const activeLines = (original || '').split(/\r?\n/).filter(line => /^\s*ignore-scripts\s*=/i.test(line));
      const alreadyEnabled = /^\s*ignore-scripts\s*=\s*true\s*(?:[#;].*)?$/i.test(activeLines.at(-1) || '');
      if (alreadyEnabled) return false; // Existing user protection is not an extension-owned modification.
      const replacement = (original || '').replace(/\s*$/, '') + '\n# Added after review by FakeInterviewGuard\nignore-scripts=true\n';
      const applied = this.changes.apply(npmrc, original, replacement);
      if (applied) this.blockedPackages.add(review.packageJsonPath);
      return applied;
    } catch (error) {
      this.outputChannel.appendLine(`[NPM-INTERCEPTOR] Change refused: ${String(error)}`);
      return false;
    }
  }

  private findLineNumber(lines: string[], search: string): number {
    for (let i = 0; i < lines.length; i++) {
      if (lines[i].includes(`"${search}"`)) {
        return i;
      }
    }
    return 0;
  }

  isBlocked(packageJsonPath: string): boolean {
    return this.blockedPackages.has(packageJsonPath);
  }

  async removeBlock(packageJsonPath: string): Promise<boolean> {
    try {
      const npmrc = path.join(path.dirname(packageJsonPath), '.npmrc');
      if (!fs.existsSync(npmrc)) return true;
      const restored = this.changes.restore(npmrc);
      if (restored) this.blockedPackages.delete(packageJsonPath);
      return restored;
    } catch { return false; }
  }
}

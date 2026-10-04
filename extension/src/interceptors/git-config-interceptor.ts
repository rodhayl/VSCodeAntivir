import * as vscode from 'vscode';
import * as fs from 'fs';
import * as path from 'path';
import { FileChange, readForReview } from '../safety/file-change';

export interface GitConfigThreat {
  type: 'fsmonitor' | 'hookspath' | 'sshcommand' | 'malicious-hook';
  severity: 'critical' | 'high';
  configKey: string;
  value: string;
  filePath: string;
  line: number;
}

export interface GitScanResult {
  hasThreats: boolean;
  threats: GitConfigThreat[];
  blocked: boolean;
  snapshots?: Record<string, string>;
}

const DANGEROUS_CONFIG_PATTERNS = [
  { key: 'core.fsmonitor', type: 'fsmonitor' as const, severity: 'critical' as const },
  { key: 'core.hookspath', type: 'hookspath' as const, severity: 'critical' as const },
  { key: 'core.sshcommand', type: 'sshcommand' as const, severity: 'high' as const },
];

const DANGEROUS_HOOK_PATTERNS = [
  /curl\s+.*\|.*sh/i,
  /wget\s+.*\|.*sh/i,
  /base64.*-d.*\|/i,
  /\beval\s*\(/,
  /Invoke-WebRequest/i,
  /Invoke-Expression/i,
];

export class GitConfigInterceptor {
  private outputChannel: vscode.OutputChannel;
  private blockedPaths = new Set<string>();
  private changes = new FileChange();
  private changedHooks = new Set<string>();
  private onThreatDetected: ((result: GitScanResult) => void) | null = null;

  constructor(outputChannel: vscode.OutputChannel) {
    this.outputChannel = outputChannel;
  }

  setThreatHandler(handler: (result: GitScanResult) => void): void {
    this.onThreatDetected = handler;
  }

  async interceptWorkspace(workspaceFolder: vscode.WorkspaceFolder): Promise<GitScanResult | null> {
    const gitDir = path.join(workspaceFolder.uri.fsPath, '.git');
    
    if (!fs.existsSync(gitDir)) {
      return null;
    }

    const result: GitScanResult = {
      hasThreats: false,
      threats: [],
      blocked: false,
      snapshots: {},
    };

    // Check .git/config
    const configPath = path.join(gitDir, 'config');
    if (fs.existsSync(configPath)) {
      const configThreats = await this.scanGitConfig(configPath, result.snapshots!);
      result.threats.push(...configThreats);
    }

    // Check git hooks
    const hooksDir = path.join(gitDir, 'hooks');
    if (fs.existsSync(hooksDir)) {
      const hookThreats = await this.scanGitHooks(hooksDir, result.snapshots!);
      result.threats.push(...hookThreats);
    }

    result.hasThreats = result.threats.length > 0;

    if (result.hasThreats && this.onThreatDetected) this.onThreatDetected(result);
    return result;
  }

  async applyBlock(review: GitScanResult): Promise<boolean> {
    const snapshots = review.snapshots;
    if (!snapshots || !review.hasThreats) return false;
    try {
      const groups = new Map<string, GitConfigThreat[]>();
      for (const threat of review.threats) groups.set(threat.filePath, [...(groups.get(threat.filePath) || []), threat]);
      for (const file of groups.keys()) if (readForReview(file) !== snapshots[file]) return false;
      let changed = 0;
      for (const [file, threats] of groups) {
        const original = snapshots[file];
        if (original === undefined) return false;
        let replacement: string;
        if (threats.some(t => t.type === 'malicious-hook')) {
          replacement = '#!/bin/sh\n# Hook disabled after review by FakeInterviewGuard\n';
        } else {
          const lines = original.split('\n');
          for (const threat of threats) lines[threat.line] = '# Disabled after review by FakeInterviewGuard: ' + lines[threat.line];
          replacement = lines.join('\n');
        }
        if (!this.changes.apply(file, original, replacement)) return false;
        this.blockedPaths.add(file);
        if (threats.some(t => t.type === 'malicious-hook')) this.changedHooks.add(file);
        changed++;
      }
      return changed > 0;
    } catch (error) {
      this.outputChannel.appendLine(`[GIT-INTERCEPTOR] Could not complete every proposed change; inspect retained backups: ${String(error)}`);
      return false;
    }
  }

  private async scanGitConfig(configPath: string, snapshots: Record<string, string>): Promise<GitConfigThreat[]> {
    const threats: GitConfigThreat[] = [];
    
    let content: string;
    try {
      content = readForReview(configPath);
      snapshots[configPath] = content;
    } catch {
      return threats;
    }

    const lines = content.split('\n');
    let currentSection = '';
    
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i].trim();
      
      // Track current section (e.g., [core], [remote "origin"])
      const sectionMatch = line.match(/^\[([^\]]+)\]/);
      if (sectionMatch) {
        currentSection = sectionMatch[1].toLowerCase();
        continue;
      }

      for (const pattern of DANGEROUS_CONFIG_PATTERNS) {
        const [section, key] = pattern.key.split('.');
        
        // Match the key within the correct section
        if (currentSection !== section.toLowerCase()) continue;

        const keyPattern = new RegExp(`^\\s*${key}\\s*=\\s*(.+)`, 'i');
        const match = line.match(keyPattern);
        
        if (match) {
          threats.push({
            type: pattern.type,
            severity: pattern.severity,
            configKey: pattern.key,
            value: match[1].trim(),
            filePath: configPath,
            line: i,
          });
        }
      }
    }

    return threats;
  }

  private async scanGitHooks(hooksDir: string, snapshots: Record<string, string>): Promise<GitConfigThreat[]> {
    const threats: GitConfigThreat[] = [];
    const dangerousHooks = [
      'pre-commit', 'post-commit', 'pre-push', 'post-checkout', 'post-merge',
      'prepare-commit-msg', 'commit-msg', 'pre-rebase', 'post-rewrite',
      'post-applypatch', 'pre-auto-gc', 'post-index-change',
    ];

    for (const hookName of dangerousHooks) {
      const hookPath = path.join(hooksDir, hookName);

      if (!fs.existsSync(hookPath)) continue;

      let content: string;
      try {
        content = readForReview(hookPath);
        snapshots[hookPath] = content;
      } catch {
        continue;
      }

      for (const pattern of DANGEROUS_HOOK_PATTERNS) {
        if (pattern.test(content)) {
          const match = content.match(pattern);
          threats.push({
            type: 'malicious-hook',
            severity: 'high',
            configKey: hookName,
            value: match?.[0] || 'suspicious pattern',
            filePath: hookPath,
            line: 0,
          });
          break;
        }
      }
    }

    return threats;
  }

  isBlocked(filePath: string): boolean { return this.blockedPaths.has(filePath); }

  async restoreHook(hookPath: string): Promise<boolean> {
    try {
      const restored = this.changes.restore(hookPath);
      if (restored) { this.changedHooks.delete(hookPath); this.blockedPaths.delete(hookPath); }
      return restored;
    } catch { return false; }
  }

  async restoreAllHooks(hooksDir: string): Promise<number> {
    let restored = 0;
    for (const hook of [...this.changedHooks]) {
      if (path.dirname(hook) === path.resolve(hooksDir) && await this.restoreHook(hook)) restored++;
    }
    return restored;
  }

  async restoreGitConfig(configPath: string): Promise<boolean> {
    try {
      const restored = this.changes.restore(configPath);
      if (restored) this.blockedPaths.delete(configPath);
      return restored;
    } catch { return false; }
  }
}

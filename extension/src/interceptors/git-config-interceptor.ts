import * as vscode from 'vscode';
import * as fs from 'fs';
import * as path from 'path';

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
    };

    // Check .git/config
    const configPath = path.join(gitDir, 'config');
    if (fs.existsSync(configPath)) {
      const configThreats = await this.scanGitConfig(configPath);
      result.threats.push(...configThreats);
    }

    // Check git hooks
    const hooksDir = path.join(gitDir, 'hooks');
    if (fs.existsSync(hooksDir)) {
      const hookThreats = await this.scanGitHooks(hooksDir);
      result.threats.push(...hookThreats);
    }

    result.hasThreats = result.threats.length > 0;

    if (result.hasThreats) {
      const hasCritical = result.threats.some(t => t.severity === 'critical');
      
      if (hasCritical) {
        result.blocked = await this.neutralizeDangerousConfig(configPath, result.threats);
        
        if (result.blocked) {
          this.outputChannel.appendLine(`[GIT-INTERCEPTOR] Neutralized dangerous git config in ${workspaceFolder.name}`);
          this.blockedPaths.add(configPath);
        }
      }

      if (this.onThreatDetected) {
        this.onThreatDetected(result);
      }
    }

    return result;
  }

  private async scanGitConfig(configPath: string): Promise<GitConfigThreat[]> {
    const threats: GitConfigThreat[] = [];
    
    let content: string;
    try {
      content = fs.readFileSync(configPath, 'utf-8');
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

  private async scanGitHooks(hooksDir: string): Promise<GitConfigThreat[]> {
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
        content = fs.readFileSync(hookPath, 'utf-8');
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

  private async neutralizeDangerousConfig(configPath: string, threats: GitConfigThreat[]): Promise<boolean> {
    const configThreats = threats.filter(t => t.type !== 'malicious-hook' && t.filePath === configPath);
    const hookThreats = threats.filter(t => t.type === 'malicious-hook');

    if (configThreats.length === 0 && hookThreats.length === 0) {
      return false;
    }

    try {
      // Neutralize dangerous config lines
      if (configThreats.length > 0) {
        let content = fs.readFileSync(configPath, 'utf-8');

        // Create backup
        const backupPath = configPath + '.fig-backup';
        if (!fs.existsSync(backupPath)) {
          fs.writeFileSync(backupPath, content, 'utf-8');
        }

        // Comment out dangerous lines
        for (const threat of configThreats) {
          const pattern = new RegExp(`(${threat.configKey.replace('.', '\\.')}\\s*=)`, 'gi');
          content = content.replace(pattern, '# BLOCKED by FakeInterviewGuard: $1');
        }

        fs.writeFileSync(configPath, content, 'utf-8');
        this.outputChannel.appendLine(`[GIT-INTERCEPTOR] Config neutralized: ${configPath}`);
        this.outputChannel.appendLine(`[GIT-INTERCEPTOR] Backup saved to: ${backupPath}`);
      }

      // Neutralize malicious hooks by renaming them
      for (const hookThreat of hookThreats) {
        const hookPath = hookThreat.filePath;
        const disabledPath = hookPath + '.fig-disabled';
        try {
          if (fs.existsSync(hookPath) && !fs.existsSync(disabledPath)) {
            fs.renameSync(hookPath, disabledPath);
            this.outputChannel.appendLine(`[GIT-INTERCEPTOR] Malicious hook disabled: ${hookPath} → ${disabledPath}`);
          }
        } catch (e: any) {
          this.outputChannel.appendLine(`[GIT-INTERCEPTOR] Failed to disable hook ${hookPath}: ${e.message}`);
        }
      }

      return true;
    } catch (e: any) {
      this.outputChannel.appendLine(`[GIT-INTERCEPTOR] Failed to neutralize: ${e.message}`);
      return false;
    }
  }

  isBlocked(filePath: string): boolean {
    return this.blockedPaths.has(filePath);
  }

  async restoreHook(hookPath: string): Promise<boolean> {
    const disabledPath = hookPath + '.fig-disabled';
    if (!fs.existsSync(disabledPath)) return false;
    try {
      fs.renameSync(disabledPath, hookPath);
      this.outputChannel.appendLine(`[GIT-INTERCEPTOR] Hook restored: ${disabledPath} → ${hookPath}`);
      return true;
    } catch (e: any) {
      this.outputChannel.appendLine(`[GIT-INTERCEPTOR] Failed to restore hook: ${e.message}`);
      return false;
    }
  }

  async restoreAllHooks(hooksDir: string): Promise<number> {
    let restored = 0;
    if (!fs.existsSync(hooksDir)) return 0;
    const entries = fs.readdirSync(hooksDir);
    for (const entry of entries) {
      if (entry.endsWith('.fig-disabled')) {
        const original = path.join(hooksDir, entry.replace('.fig-disabled', ''));
        if (await this.restoreHook(original)) restored++;
      }
    }
    return restored;
  }
}

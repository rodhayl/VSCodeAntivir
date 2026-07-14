import * as vscode from 'vscode';
import * as fs from 'fs';
import * as path from 'path';

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
}

const DANGEROUS_SCRIPTS = ['preinstall', 'postinstall', 'prestart', 'prepare'];

const DANGEROUS_INDICATORS = [
  { pattern: /\bnode\s+\S+\.js/i, reason: 'Executes external JS file' },
  { pattern: /\bcurl\s+/i, reason: 'Network download in install script' },
  { pattern: /\bwget\s+/i, reason: 'Network download in install script' },
  { pattern: /\beval\b/i, reason: 'Dynamic code execution' },
  { pattern: /\bexec\b/i, reason: 'Shell command execution' },
  { pattern: /https?:\/\//i, reason: 'Network URL in install script' },
  { pattern: /\bsh\s+-c\b/i, reason: 'Shell command execution' },
  { pattern: /\bbash\s+-c\b/i, reason: 'Shell command execution' },
  { pattern: /\bpowershell\b/i, reason: 'PowerShell execution' },
  { pattern: /\bcmd\s+\/c\b/i, reason: 'CMD execution' },
  { pattern: /setup_bun|bun_environment/i, reason: 'Known Contagious Interview pattern' },
];

export class NpmScriptInterceptor {
  private outputChannel: vscode.OutputChannel;
  private blockedPackages = new Set<string>();
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
      content = fs.readFileSync(packageJsonPath, 'utf-8');
    } catch {
      return result;
    }

    let pkg: any;
    try {
      pkg = JSON.parse(content);
    } catch {
      return result;
    }

    const scripts = pkg.scripts || {};
    const lines = content.split('\n');

    for (const scriptName of DANGEROUS_SCRIPTS) {
      const scriptCommand = scripts[scriptName];
      if (!scriptCommand) continue;

      for (const indicator of DANGEROUS_INDICATORS) {
        if (indicator.pattern.test(scriptCommand)) {
          const lineNum = this.findLineNumber(lines, scriptName);
          result.threats.push({
            scriptName,
            scriptCommand: scriptCommand.substring(0, 200),
            severity: scriptName === 'preinstall' ? 'critical' : 'high',
            reason: indicator.reason,
            line: lineNum,
          });
          break;
        }
      }
    }

    result.hasThreats = result.threats.length > 0;

    if (result.hasThreats) {
      const hasCritical = result.threats.some(t => t.severity === 'critical');
      
      if (hasCritical) {
        result.npmrcModified = await this.blockNpmScripts(packageJsonPath);
        result.blocked = result.npmrcModified;
        
        if (result.blocked) {
          this.outputChannel.appendLine(`[BLOCKED] Disabled npm scripts for: ${packageJsonPath}`);
          this.blockedPackages.add(packageJsonPath);
        }
      }

      if (this.onThreatDetected) {
        this.onThreatDetected(result);
      }
    }

    return result;
  }

  private async blockNpmScripts(packageJsonPath: string): Promise<boolean> {
    const dir = path.dirname(packageJsonPath);
    const npmrcPath = path.join(dir, '.npmrc');

    try {
      let npmrcContent = '';
      let alreadyHasIgnore = false;

      if (fs.existsSync(npmrcPath)) {
        npmrcContent = fs.readFileSync(npmrcPath, 'utf-8');
        alreadyHasIgnore = npmrcContent.includes('ignore-scripts');
      }

      if (alreadyHasIgnore) {
        return true;
      }

      const newContent = npmrcContent.trim() + 
        '\n# Added by FakeInterviewGuard - malicious install scripts detected\n' +
        'ignore-scripts=true\n';

      fs.writeFileSync(npmrcPath, newContent, 'utf-8');

      this.outputChannel.appendLine(`[NPM-INTERCEPTOR] Created/modified .npmrc with ignore-scripts=true`);
      return true;
    } catch (e: any) {
      this.outputChannel.appendLine(`[NPM-INTERCEPTOR] Failed to modify .npmrc: ${e.message}`);
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
    const dir = path.dirname(packageJsonPath);
    const npmrcPath = path.join(dir, '.npmrc');

    if (!fs.existsSync(npmrcPath)) {
      this.blockedPackages.delete(packageJsonPath);
      return true;
    }

    try {
      let content = fs.readFileSync(npmrcPath, 'utf-8');
      
      content = content
        .replace(/# Added by FakeInterviewGuard.*\n?/g, '')
        .replace(/ignore-scripts=true\n?/g, '')
        .trim();

      if (content.length === 0) {
        fs.unlinkSync(npmrcPath);
      } else {
        fs.writeFileSync(npmrcPath, content + '\n', 'utf-8');
      }

      this.blockedPackages.delete(packageJsonPath);
      this.outputChannel.appendLine(`[NPM-INTERCEPTOR] Removed script blocking for: ${packageJsonPath}`);
      return true;
    } catch {
      return false;
    }
  }
}

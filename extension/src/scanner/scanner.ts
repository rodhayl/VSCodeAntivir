import * as fs from 'fs';
import * as path from 'path';
import { DetectionRule } from './models/rule';
import { Threat } from './models/threat';
import { ScanResult, ScanSummary, createEmptySummary } from './models/scan-result';
import { Severity, severityToString } from './models/severity';
import { RuleLoader } from '../rules/rule-loader';
import { runSignatureEngine } from './engines/signature-engine';
import { runHeuristicEngine } from './engines/heuristic-engine';
import { runNpmAuditEngine } from './engines/npm-audit-engine';
import { runVscodeTaskEngine } from './engines/vscode-task-engine';
import { minimatch } from 'minimatch';

export class Scanner {
  private rules: DetectionRule[] = [];
  private ruleLoader: RuleLoader;
  private excludedPatterns: string[] = ['**/node_modules/**', '**/.git/**'];
  private maxFileSizeKB = 512;

  constructor() {
    this.ruleLoader = new RuleLoader();
  }

  loadRules(builtInRulesDir: string, customRulesDir?: string): { count: number; errors: string[] } {
    this.ruleLoader.clear();
    this.ruleLoader.loadFromDirectory(builtInRulesDir);
    if (customRulesDir) {
      this.ruleLoader.loadFromDirectory(customRulesDir);
    }
    this.rules = this.ruleLoader.getRules();
    return { count: this.rules.length, errors: this.ruleLoader.getErrors() };
  }

  getRules(): DetectionRule[] {
    return [...this.rules];
  }

  setExcludedPatterns(patterns: string[]): void {
    this.excludedPatterns = patterns;
  }

  setMaxFileSizeKB(kb: number): void {
    this.maxFileSizeKB = kb;
  }

  scanFile(filePath: string, content?: string): ScanResult {
    const start = Date.now();
    const fileContent = content ?? fs.readFileSync(filePath, 'utf-8');
    const threats: Threat[] = [];

    // Run signature engine (rule-based)
    threats.push(...runSignatureEngine(fileContent, filePath, this.rules));

    // Run heuristic engine
    threats.push(...runHeuristicEngine(fileContent, filePath));

    // Run npm audit engine
    threats.push(...runNpmAuditEngine(fileContent, filePath));

    // Run VS Code task engine
    threats.push(...runVscodeTaskEngine(fileContent, filePath));

    return {
      filePath,
      threats,
      scanDurationMs: Date.now() - start,
    };
  }

  scanWorkspace(rootDir: string): ScanSummary {
    const start = Date.now();
    const summary = createEmptySummary();
    const files = this.walkDirectory(rootDir);
    summary.totalFiles = files.length;

    for (const file of files) {
      if (this.shouldSkip(file, rootDir)) {
        summary.skippedFiles++;
        continue;
      }

      try {
        const stat = fs.statSync(file);
        if (stat.size > this.maxFileSizeKB * 1024) {
          summary.skippedFiles++;
          continue;
        }
        const result = this.scanFile(file);
        summary.scannedFiles++;
        summary.results.push(result);
        for (const threat of result.threats) {
          summary.totalThreats++;
          const key = severityToString(threat.severity);
          summary.threatsBySeverity[key] = (summary.threatsBySeverity[key] || 0) + 1;
        }
      } catch {
        summary.skippedFiles++;
      }
    }

    summary.durationMs = Date.now() - start;
    return summary;
  }

  private shouldSkip(filePath: string, rootDir: string): boolean {
    const relativePath = path.relative(rootDir, filePath).replace(/\\/g, '/');
    return this.excludedPatterns.some(pattern => minimatch(relativePath, pattern));
  }

  private walkDirectory(dir: string): string[] {
    const results: string[] = [];
    const scanExts = ['.js', '.mjs', '.ts', '.py', '.ps1', '.sh', '.json', '.html'];
    try {
      const entries = fs.readdirSync(dir, { withFileTypes: true });
      for (const entry of entries) {
        const fullPath = path.join(dir, entry.name);
        if (entry.isDirectory()) {
          if (entry.name === 'node_modules' || entry.name === '.git' || entry.name === 'out') continue;
          results.push(...this.walkDirectory(fullPath));
        } else if (entry.isFile()) {
          const ext = path.extname(entry.name).toLowerCase();
          if (scanExts.includes(ext)) {
            results.push(fullPath);
          }
        }
      }
    } catch { /* skip unreadable dirs */ }
    return results;
  }
}

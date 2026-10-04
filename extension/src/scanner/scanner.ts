import * as fs from 'fs';
import * as path from 'path';
import { DetectionRule } from './models/rule';
import { Threat } from './models/threat';
import { ScanResult, ScanSummary, createEmptySummary } from './models/scan-result';
import { severityToString } from './models/severity';
import { RuleLoader } from '../rules/rule-loader';
import { runSignatureEngine } from './engines/signature-engine';
import { runHeuristicEngine } from './engines/heuristic-engine';
import { runNpmAuditEngine } from './engines/npm-audit-engine';
import { runVscodeTaskEngine } from './engines/vscode-task-engine';
import { minimatch } from 'minimatch';
import { parse, ParseError } from 'jsonc-parser';

export class Scanner {
  private rules: DetectionRule[] = [];
  private ruleLoader: RuleLoader;
  private excludedPatterns: string[] = ['**/node_modules/**', '**/.git/**'];
  private maxFileSizeKB = 512;

  constructor() {
    this.ruleLoader = new RuleLoader();
  }

  loadRules(
    builtInRulesDir: string,
    customRulesDir?: string,
    enabledRuleSets?: string[]
  ): { count: number; errors: string[] } {
    this.ruleLoader.clear();

    const selectedRuleSets = new Set(enabledRuleSets ?? []);
    const builtInEntries = fs.existsSync(builtInRulesDir)
      ? fs.readdirSync(builtInRulesDir, { withFileTypes: true })
      : [];

    for (const entry of builtInEntries) {
      if (!entry.isDirectory()) {
        continue;
      }

      if (selectedRuleSets.size > 0 && !selectedRuleSets.has(entry.name)) {
        continue;
      }

      this.ruleLoader.loadFromDirectory(path.join(builtInRulesDir, entry.name));
    }

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
    this.maxFileSizeKB = Number.isFinite(kb) && kb > 0 ? kb : 512;
  }

  getMaxFileSizeKB(): number {
    return this.maxFileSizeKB;
  }

  getSkipReason(filePath: string, rootDir?: string, content?: string): string | undefined {
    const relative = (rootDir ? path.relative(rootDir, filePath) : filePath).replace(/\\/g, '/');
    if (this.excludedPatterns.some(pattern => minimatch(relative, pattern, { dot: true }))) return 'Excluded by configuration';
    const size = content === undefined ? fs.statSync(filePath).size : Buffer.byteLength(content, 'utf8');
    return size > this.maxFileSizeKB * 1024 ? 'File exceeds configured size limit' : undefined;
  }

  scanFile(filePath: string, content?: string, rootDir?: string): ScanResult {
    const start = Date.now();
    let fileContent: string;
    try {
      const detail = this.getSkipReason(filePath, rootDir, content);
      if (detail) return { filePath, threats: [], scanDurationMs: Date.now() - start, status: 'skipped', detail };
      fileContent = content ?? fs.readFileSync(filePath, 'utf-8');
    } catch (error) {
      return { filePath, threats: [], scanDurationMs: Date.now() - start, status: 'error', detail: String(error) };
    }
    if (path.basename(filePath) === 'tasks.json' || path.basename(filePath) === 'package.json') {
      try {
        if (path.basename(filePath) === 'tasks.json') {
          const errors: ParseError[] = [];
          const tasks = parse(fileContent, errors, { allowTrailingComma: true });
          if (errors.length || !tasks || !Array.isArray(tasks.tasks ?? [])) throw new Error('Invalid task configuration');
        } else { JSON.parse(fileContent); }
      } catch (error) {
        return { filePath, threats: [], scanDurationMs: Date.now() - start, status: 'error', detail: `Configuration parse failed: ${String(error)}` };
      }
    }
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
      status: 'scanned',
    };
  }

  scanWorkspace(rootDir: string): ScanSummary {
    const start = Date.now();
    const summary = createEmptySummary();
    const files = this.walkDirectory(rootDir, summary.errors);
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
        const result = this.scanFile(file, undefined, rootDir);
        if (result.status === 'error') { summary.failedFiles++; summary.errors.push(result.detail || file); continue; }
        if (result.status === 'skipped') { summary.skippedFiles++; continue; }
        summary.scannedFiles++;
        summary.results.push(result);
        for (const threat of result.threats) {
          summary.totalThreats++;
          const key = severityToString(threat.severity);
          summary.threatsBySeverity[key] = (summary.threatsBySeverity[key] || 0) + 1;
        }
      } catch (error) {
        summary.failedFiles++; summary.errors.push(String(error));
      }
    }

    summary.durationMs = Date.now() - start;
    return summary;
  }

  private shouldSkip(filePath: string, rootDir: string): boolean {
    const relativePath = path.relative(rootDir, filePath).replace(/\\/g, '/');
    return this.excludedPatterns.some(pattern => minimatch(relativePath, pattern, { dot: true }));
  }

  private walkDirectory(dir: string, errors: string[]): string[] {
    const results: string[] = [];
    const scanExts = ['.js', '.mjs', '.ts', '.py', '.ps1', '.sh', '.json', '.html', '.yml', '.yaml', '.go', '.mod'];
    try {
      const entries = fs.readdirSync(dir, { withFileTypes: true });
      for (const entry of entries) {
        const fullPath = path.join(dir, entry.name);
        if (entry.isDirectory()) {
          if (entry.name === 'node_modules' || entry.name === '.git' || entry.name === 'out') continue;
          results.push(...this.walkDirectory(fullPath, errors));
        } else if (entry.isFile()) {
          const ext = path.extname(entry.name).toLowerCase();
          if (scanExts.includes(ext)) {
            results.push(fullPath);
          }
        }
      }
    } catch (error) { errors.push(`Cannot enumerate ${dir}: ${String(error)}`); }
    return results;
  }
}

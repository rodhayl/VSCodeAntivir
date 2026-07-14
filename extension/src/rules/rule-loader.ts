import * as fs from 'fs';
import * as path from 'path';
import { DetectionRule } from '../scanner/models/rule';

export class RuleLoader {
  private rules: DetectionRule[] = [];
  private errors: string[] = [];

  loadFromDirectory(dirPath: string): void {
    if (!fs.existsSync(dirPath)) return;
    const files = this.findJsonFiles(dirPath);
    for (const file of files) {
      try {
        const content = fs.readFileSync(file, 'utf-8');
        const rule = JSON.parse(content) as DetectionRule;
        if (this.validateRule(rule, file)) {
          this.rules.push(rule);
        }
      } catch (e: any) {
        this.errors.push(`Failed to load rule from ${file}: ${e.message}`);
      }
    }
  }

  private findJsonFiles(dirPath: string): string[] {
    const results: string[] = [];
    const entries = fs.readdirSync(dirPath, { withFileTypes: true });
    for (const entry of entries) {
      const fullPath = path.join(dirPath, entry.name);
      if (entry.isDirectory()) {
        results.push(...this.findJsonFiles(fullPath));
      } else if (entry.name.endsWith('.json') && !entry.name.startsWith('_')) {
        results.push(fullPath);
      }
    }
    return results;
  }

  private validateRule(rule: any, filePath: string): boolean {
    if (!rule.id || typeof rule.id !== 'string') {
      this.errors.push(`Rule in ${filePath} missing 'id'`);
      return false;
    }
    if (!rule.name || typeof rule.name !== 'string') {
      this.errors.push(`Rule ${rule.id} missing 'name'`);
      return false;
    }
    if (!rule.severity || !['critical', 'high', 'medium', 'low', 'info'].includes(rule.severity)) {
      this.errors.push(`Rule ${rule.id} has invalid severity: ${rule.severity}`);
      return false;
    }
    if (!rule.matchers || !Array.isArray(rule.matchers) || rule.matchers.length === 0) {
      this.errors.push(`Rule ${rule.id} has no matchers`);
      return false;
    }
    if (!rule.condition) {
      this.errors.push(`Rule ${rule.id} missing condition`);
      return false;
    }
    if (!rule.appliesTo) {
      this.errors.push(`Rule ${rule.id} missing appliesTo`);
      return false;
    }
    return true;
  }

  getRules(): DetectionRule[] {
    return [...this.rules];
  }

  getErrors(): string[] {
    return [...this.errors];
  }

  clear(): void {
    this.rules = [];
    this.errors = [];
  }
}

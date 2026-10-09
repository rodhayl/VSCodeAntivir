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
      } catch (e: unknown) {
        this.errors.push(`Failed to load rule from ${file}: ${e instanceof Error ? e.message : String(e)}`);
      }
    }
  }

  private findJsonFiles(dirPath: string): string[] {
    const results: string[] = [];
    let entries: fs.Dirent[];
    try {
      entries = fs.readdirSync(dirPath, { withFileTypes: true });
    } catch {
      return results;
    }
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

  private validateRule(rule: DetectionRule, filePath: string): boolean {
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
    // Validate each matcher has required fields
    const validMatcherTypes = ['string', 'string-any', 'regex', 'entropy', 'ast'];
    for (const matcher of rule.matchers) {
      if (!matcher.id || typeof matcher.id !== 'string') {
        this.errors.push(`Rule ${rule.id} matcher missing 'id'`);
        return false;
      }
      if (!matcher.type || !validMatcherTypes.includes(matcher.type)) {
        this.errors.push(`Rule ${rule.id} matcher ${matcher.id} has invalid type: ${matcher.type}`);
        return false;
      }
      if ((matcher.type === 'string' || matcher.type === 'ast') && (typeof matcher.pattern !== 'string' || !matcher.pattern)) {
        this.errors.push(`Rule ${rule.id} string matcher ${matcher.id} missing 'pattern'`);
        return false;
      }
      if (matcher.type === 'string-any' && (!Array.isArray(matcher.patterns) || !matcher.patterns.length || matcher.patterns.some((pattern: unknown) => typeof pattern !== 'string' || !pattern))) {
        this.errors.push(`Rule ${rule.id} string-any matcher ${matcher.id} missing 'patterns' array`);
        return false;
      }
      if (matcher.type === 'regex' && (typeof matcher.pattern !== 'string' || !matcher.pattern)) {
        this.errors.push(`Rule ${rule.id} regex matcher ${matcher.id} missing 'pattern'`);
        return false;
      }
      if (matcher.type === 'regex') {
        try { new RegExp(matcher.pattern, matcher.flags || 'i'); } catch { this.errors.push(`Rule ${rule.id} has an invalid regular expression`); return false; }
      }
      if (matcher.type === 'entropy' && (matcher.threshold === undefined || matcher.minLength === undefined)) {
        this.errors.push(`Rule ${rule.id} entropy matcher ${matcher.id} missing 'threshold' or 'minLength'`);
        return false;
      }
    }
    // Validate condition
    if (!rule.condition || !rule.condition.type || !['all', 'any', 'threshold'].includes(rule.condition.type)) {
      this.errors.push(`Rule ${rule.id} missing or invalid condition`);
      return false;
    }
    if (!rule.condition.of || !Array.isArray(rule.condition.of) || rule.condition.of.length === 0) {
      this.errors.push(`Rule ${rule.id} condition missing 'of' array`);
      return false;
    }
    const matcherIds = new Set(rule.matchers.map(m => m.id));
    for (const ref of rule.condition.of) {
      if (!matcherIds.has(ref)) {
        this.errors.push(`Rule ${rule.id} condition.of references unknown matcher: "${ref}"`);
        return false;
      }
    }
    if (rule.condition.type === 'threshold' && typeof rule.condition.minimum !== 'number') {
      this.errors.push(`Rule ${rule.id} threshold condition missing 'minimum'`);
      return false;
    }
    // Validate appliesTo
    if (!rule.appliesTo) {
      this.errors.push(`Rule ${rule.id} missing appliesTo`);
      return false;
    }
    if (rule.appliesTo.filePatterns && !Array.isArray(rule.appliesTo.filePatterns)) {
      this.errors.push(`Rule ${rule.id} appliesTo.filePatterns must be an array`);
      return false;
    }
    if (rule.appliesTo.languages && !Array.isArray(rule.appliesTo.languages)) {
      this.errors.push(`Rule ${rule.id} appliesTo.languages must be an array`);
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

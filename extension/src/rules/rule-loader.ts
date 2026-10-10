import * as fs from 'fs';
import * as path from 'path';
import { DetectionRule } from '../scanner/models/rule';

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function isNonEmptyString(value: unknown): value is string {
  return typeof value === 'string' && value.trim().length > 0;
}

function isStringArray(value: unknown): value is string[] {
  return Array.isArray(value) && value.every(isNonEmptyString);
}

export class RuleLoader {
  private rules: DetectionRule[] = [];
  private errors: string[] = [];

  loadFromDirectory(dirPath: string): void {
    if (!fs.existsSync(dirPath)) return;
    const files = this.findJsonFiles(dirPath);
    for (const file of files) {
      try {
        const content = fs.readFileSync(file, 'utf-8');
        const rule: unknown = JSON.parse(content);
        if (this.validateRule(rule, file)) {
          if (this.rules.some(loaded => loaded.id === rule.id)) {
            this.errors.push(`Rule in ${file} has duplicate rule id: ${rule.id}`);
            continue;
          }
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
    return results.sort();
  }

  private validateRule(rule: unknown, filePath: string): rule is DetectionRule {
    const fail = (message: string): false => {
      this.errors.push(`Rule in ${filePath}: ${message}`);
      return false;
    };
    if (!isRecord(rule)) return fail('expected a rule object');
    if (!isNonEmptyString(rule.id)) return fail("missing or invalid 'id'");
    if (!isNonEmptyString(rule.name)) return fail(`Rule ${rule.id} missing or invalid 'name'`);
    if (typeof rule.severity !== 'string' || !['critical', 'high', 'medium', 'low', 'info'].includes(rule.severity)) {
      return fail(`Rule ${rule.id} has invalid severity`);
    }

    // Validate optional metadata before it reaches diagnostics and webviews.
    // Description/confidence were historically optional in custom JSON rules.
    for (const key of ['description', 'confidence', 'version', 'category', 'campaign']) {
      if (rule[key] !== undefined && typeof rule[key] !== 'string') return fail(`${key} must be a string`);
    }
    for (const key of ['references', 'tags']) {
      if (rule[key] !== undefined && !isStringArray(rule[key])) return fail(`${key} must be an array of non-empty strings`);
    }
    const mitre = rule.mitre;
    if (mitre !== undefined && (!isRecord(mitre) || !['tactic', 'technique'].every(key => isNonEmptyString(mitre[key])) ||
        (mitre.name !== undefined && typeof mitre.name !== 'string'))) {
      return fail('mitre must contain string tactic and technique fields, with an optional string name');
    }
    if (rule.remediation !== undefined) {
      if (!isRecord(rule.remediation) || typeof rule.remediation.message !== 'string' || !isStringArray(rule.remediation.actions)) {
        return fail('remediation must contain a string message and an array of string actions');
      }
      if (rule.remediation.references !== undefined && !isStringArray(rule.remediation.references)) {
        return fail('remediation.references must be an array of non-empty strings');
      }
    }

    if (!isRecord(rule.appliesTo)) return fail('missing or invalid appliesTo object');
    for (const key of ['filePatterns', 'languages']) {
      if (rule.appliesTo[key] !== undefined && !isStringArray(rule.appliesTo[key])) {
        return fail(`appliesTo.${key} must be an array of non-empty strings`);
      }
    }
    // minimatch rejects longer patterns at runtime. Reject them at the load boundary.
    if (isStringArray(rule.appliesTo.filePatterns) && rule.appliesTo.filePatterns.some(pattern => pattern.length > 64 * 1024)) {
      return fail('appliesTo.filePatterns entries must not exceed 65536 characters');
    }
    if (!Array.isArray(rule.matchers) || rule.matchers.length === 0) return fail('rule has no matchers');
    const matcherIds = new Set<string>();
    for (const matcher of rule.matchers) {
      if (!isRecord(matcher) || !isNonEmptyString(matcher.id)) return fail("matcher missing or invalid 'id'");
      if (matcherIds.has(matcher.id)) return fail(`duplicate matcher id: ${matcher.id}`);
      matcherIds.add(matcher.id);
      if (typeof matcher.type !== 'string' || !['string', 'string-any', 'regex', 'entropy', 'ast'].includes(matcher.type)) {
        return fail(`matcher ${matcher.id} has invalid type`);
      }
      if (['string', 'regex', 'ast'].includes(matcher.type) && (typeof matcher.pattern !== 'string' || matcher.pattern.length === 0)) {
        return fail(`matcher ${matcher.id} missing string pattern`);
      }
      if (matcher.type === 'string-any') {
        if (!isStringArray(matcher.patterns) || matcher.patterns.length === 0) return fail(`matcher ${matcher.id} requires non-empty string patterns`);
        if (matcher.caseSensitive !== undefined && typeof matcher.caseSensitive !== 'boolean') return fail(`matcher ${matcher.id} caseSensitive must be boolean`);
      }
      if (matcher.type === 'string' || matcher.type === 'string-any') {
        if (matcher.context !== undefined && (typeof matcher.context !== 'string' || !['file', 'imports', 'identifiers', 'strings'].includes(matcher.context))) {
          return fail(`matcher ${matcher.id} has invalid context`);
        }
      }
      if (matcher.type === 'regex' || matcher.type === 'ast') {
        if (typeof matcher.pattern !== 'string') return fail(`matcher ${matcher.id} requires a string pattern`);
        if (matcher.type === 'regex' && matcher.flags !== undefined && typeof matcher.flags !== 'string') return fail(`matcher ${matcher.id} flags must be a string`);
        if (matcher.type === 'ast' && matcher.language !== undefined && !isNonEmptyString(matcher.language)) return fail(`matcher ${matcher.id} language must be a string`);
        // Legacy ast aliases are regex-safe names; other ast patterns run as regex.
        try {
          const flags = matcher.type === 'regex' && typeof matcher.flags === 'string' ? matcher.flags || 'i' : 'i';
          new RegExp(matcher.pattern, flags);
        } catch { return fail(`matcher ${matcher.id} has an invalid regular expression`); }
      }
      if (matcher.type === 'entropy') {
        if (typeof matcher.threshold !== 'number' || !Number.isFinite(matcher.threshold) || matcher.threshold < 0) {
          return fail(`matcher ${matcher.id} threshold must be a finite non-negative number`);
        }
        if (typeof matcher.minLength !== 'number' || !Number.isSafeInteger(matcher.minLength) || matcher.minLength < 1) {
          return fail(`matcher ${matcher.id} minLength must be a positive safe integer`);
        }
        if (matcher.context !== undefined && matcher.context !== 'file' && matcher.context !== 'string_literals') {
          return fail(`matcher ${matcher.id} has invalid context`);
        }
      }
    }

    const condition = rule.condition;
    if (!isRecord(condition) || typeof condition.type !== 'string' || !['all', 'any', 'threshold'].includes(condition.type)) {
      return fail('missing or invalid condition');
    }
    const conditionFields = condition.type === 'threshold' ? ['type', 'of', 'minimum'] : ['type', 'of'];
    const unsupportedFields = Object.keys(condition).filter(key => !conditionFields.includes(key));
    if (unsupportedFields.length > 0) return fail(`unsupported condition fields: ${unsupportedFields.join(', ')}`);
    if (!isStringArray(condition.of) || condition.of.length === 0) return fail('condition.of must be a non-empty array of strings');
    if (new Set(condition.of).size !== condition.of.length) return fail('condition.of has duplicate matcher references');
    for (const ref of condition.of) {
      if (!matcherIds.has(ref)) return fail(`condition.of references unknown matcher: "${ref}"`);
    }
    if (condition.type === 'threshold' && (typeof condition.minimum !== 'number' || !Number.isSafeInteger(condition.minimum) ||
        condition.minimum < 1 || condition.minimum > condition.of.length)) {
      return fail('threshold condition minimum must be a safe integer between 1 and the number of referenced matchers');
    }

    // Preserve the documented minimal custom-rule format with safe output types.
    rule.description ??= rule.name;
    rule.confidence ??= 'medium';
    if (isRecord(rule.mitre)) rule.mitre.name ??= '';
    rule.appliesTo.filePatterns ??= [];
    rule.appliesTo.languages ??= [];
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

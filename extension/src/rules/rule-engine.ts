import { DetectionRule, Matcher, RuleCondition } from '../scanner/models/rule';
import { Threat, ThreatLocation } from '../scanner/models/threat';
import { stringToSeverity } from '../scanner/models/severity';
import { findHighEntropyStrings } from '../scanner/analyzers/entropy-analyzer';
import { minimatch } from 'minimatch';

export interface MatchResult {
  matcherId: string;
  matched: boolean;
  evidence: string[];
  locations: ThreatLocation[];
}

function getLineCol(content: string, index: number): { line: number; col: number } {
  let line = 0, col = 0;
  for (let i = 0; i < Math.min(index, content.length); i++) {
    if (content[i] === '\n') { line++; col = 0; } else { col++; }
  }
  return { line, col };
}

function runMatcher(matcher: Matcher, content: string, _filePath: string): MatchResult {
  const result: MatchResult = { matcherId: matcher.id, matched: false, evidence: [], locations: [] };

  switch (matcher.type) {
    case 'string': {
      const idx = content.indexOf(matcher.pattern);
      if (idx >= 0) {
        result.matched = true;
        result.evidence.push(matcher.pattern);
        const { line, col } = getLineCol(content, idx);
        result.locations.push({ startLine: line, startCol: col, endLine: line, endCol: col + matcher.pattern.length });
      }
      break;
    }

    case 'string-any': {
      const caseSensitive = matcher.caseSensitive !== false;
      const searchContent = caseSensitive ? content : content.toLowerCase();
      for (const pat of matcher.patterns) {
        const searchPat = caseSensitive ? pat : pat.toLowerCase();
        const idx = searchContent.indexOf(searchPat);
        if (idx >= 0) {
          result.matched = true;
          result.evidence.push(pat);
          const { line, col } = getLineCol(content, idx);
          result.locations.push({ startLine: line, startCol: col, endLine: line, endCol: col + pat.length });
        }
      }
      break;
    }

    case 'regex': {
      try {
        const flags = matcher.flags || 'i';
        const re = new RegExp(matcher.pattern, flags);
        const match = re.exec(content);
        if (match) {
          result.matched = true;
          result.evidence.push(match[0].substring(0, 100));
          const { line, col } = getLineCol(content, match.index);
          result.locations.push({ startLine: line, startCol: col, endLine: line, endCol: col + match[0].length });
        }
      } catch { /* invalid regex */ }
      break;
    }

    case 'entropy': {
      const findings = findHighEntropyStrings(content, matcher.threshold, matcher.minLength);
      if (findings.length > 0) {
        result.matched = true;
        for (const f of findings.slice(0, 3)) {
          result.evidence.push(`High entropy string (${f.entropy.toFixed(2)}): "${f.value.substring(0, 40)}..."`);
          const { line, col } = getLineCol(content, f.index);
          result.locations.push({ startLine: line, startCol: col, endLine: line, endCol: col + 10 });
        }
      }
      break;
    }

    case 'ast': {
      // Legacy compatibility alias: regex patterns, not AST analysis
      const astPatterns: Record<string, RegExp> = {
        'eval_call': /\beval\s*\(/g,
        'require_child_process': /require\s*\(\s*['"]child_process['"]\s*\)/g,
        'buffer_from_hex': /Buffer\.from\s*\([^)]*,\s*['"]hex['"]\s*\)/g,
        'socket_connect': /\.connect\s*\(\s*['"`]/g,
        'set_interval_net': /setInterval\s*\(/g,
      };
      const patternKey = matcher.pattern.toLowerCase().replace(/[^a-z_]/g, '_');
      const re = astPatterns[patternKey];
      if (re) {
        const match = re.exec(content);
        if (match) {
          result.matched = true;
          result.evidence.push(match[0]);
          const { line, col } = getLineCol(content, match.index);
          result.locations.push({ startLine: line, startCol: col, endLine: line, endCol: col + match[0].length });
        }
      } else {
        // Fallback: treat the pattern as a regex
        try {
          const fallback = new RegExp(matcher.pattern, 'i');
          const match = fallback.exec(content);
          if (match) {
            result.matched = true;
            result.evidence.push(match[0].substring(0, 100));
            const { line, col } = getLineCol(content, match.index);
            result.locations.push({ startLine: line, startCol: col, endLine: line, endCol: col + match[0].length });
          }
        } catch { /* ignore */ }
      }
      break;
    }
  }

  return result;
}

function evaluateCondition(condition: RuleCondition, matchResults: Map<string, MatchResult>): boolean {
  const matcherIds = condition.of;
  const matched = matcherIds.filter(id => matchResults.get(id)?.matched);

  switch (condition.type) {
    case 'all':
      return matched.length === matcherIds.length;
    case 'any':
      return matched.length > 0;
    case 'threshold':
      return matched.length >= condition.minimum;
    default:
      return false;
  }
}

export function executeRule(rule: DetectionRule, content: string, filePath: string): Threat | null {
  // Check if rule applies to this file
  if (rule.appliesTo.filePatterns && rule.appliesTo.filePatterns.length > 0) {
    const normalizedPath = filePath.replace(/\\/g, '/');
    const matches = rule.appliesTo.filePatterns.some(pattern => {
      return minimatch(normalizedPath, pattern, { matchBase: true }) ||
             minimatch(normalizedPath.split('/').pop() || '', pattern.replace(/\*\*\//g, ''));
    });
    if (!matches) {
      // Try matching just the extension
      const ext = '.' + (filePath.split('.').pop() || '');
      const extMatch = rule.appliesTo.filePatterns.some(p => p.endsWith(ext) || p === `**/*${ext}`);
      if (!extMatch) return null;
    }
  }

  // Run all matchers
  const matchResults = new Map<string, MatchResult>();
  for (const matcher of rule.matchers) {
    matchResults.set(matcher.id, runMatcher(matcher, content, filePath));
  }

  // Evaluate condition
  if (!evaluateCondition(rule.condition, matchResults)) return null;

  // Collect evidence
  const allEvidence: string[] = [];
  const allLocations: ThreatLocation[] = [];
  for (const [, result] of matchResults) {
    if (result.matched) {
      allEvidence.push(...result.evidence);
      allLocations.push(...result.locations);
    }
  }

  const location = allLocations[0] || { startLine: 0, startCol: 0, endLine: 0, endCol: 0 };

  return {
    id: `${rule.id}-${Date.now()}`,
    ruleId: rule.id,
    ruleName: rule.name,
    severity: stringToSeverity(rule.severity),
    confidence: rule.confidence || 'medium',
    message: rule.description,
    filePath,
    location,
    mitre: rule.mitre,
    matchedStrings: allEvidence.slice(0, 10),
    remediation: rule.remediation ? {
      message: rule.remediation.message,
      actions: rule.remediation.actions,
    } : undefined,
  };
}

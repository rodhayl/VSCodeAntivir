export interface MatcherBase {
  id: string;
  type: string;
}

export interface StringMatcher extends MatcherBase {
  type: 'string';
  pattern: string;
  context?: 'file' | 'imports' | 'identifiers' | 'strings';
}

export interface StringAnyMatcher extends MatcherBase {
  type: 'string-any';
  patterns: string[];
  context?: 'file' | 'imports' | 'identifiers' | 'strings';
  caseSensitive?: boolean;
}

export interface RegexMatcher extends MatcherBase {
  type: 'regex';
  pattern: string;
  flags?: string;
}

export interface EntropyMatcher extends MatcherBase {
  type: 'entropy';
  threshold: number;
  minLength: number;
  context?: 'string_literals' | 'file';
}

export interface AstMatcher extends MatcherBase {
  type: 'ast';
  pattern: string;
  language?: string;
}

export interface FileStructureMatcher extends MatcherBase {
  type: 'file-structure';
  requiredFiles: string[];
}

export type Matcher =
  | StringMatcher
  | StringAnyMatcher
  | RegexMatcher
  | EntropyMatcher
  | AstMatcher
  | FileStructureMatcher;

export interface ConditionAll {
  type: 'all';
  of: string[];
}

export interface ConditionAny {
  type: 'any';
  of: string[];
}

export interface ConditionThreshold {
  type: 'threshold';
  minimum: number;
  of: string[];
}

export type RuleCondition = ConditionAll | ConditionAny | ConditionThreshold;

export interface DetectionRule {
  id: string;
  name: string;
  version?: string;
  severity: string;
  confidence: string;
  description: string;
  category?: string;
  campaign?: string;
  references?: string[];
  mitre?: {
    tactic: string;
    technique: string;
    name: string;
  };
  appliesTo: {
    languages: string[];
    filePatterns: string[];
  };
  matchers: Matcher[];
  condition: RuleCondition;
  remediation?: {
    message: string;
    actions: string[];
    references?: string[];
  };
}

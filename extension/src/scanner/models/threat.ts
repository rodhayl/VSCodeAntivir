import { Severity } from './severity';

export interface ThreatLocation {
  startLine: number;
  startCol: number;
  endLine: number;
  endCol: number;
}

export interface MitreInfo {
  tactic: string;
  technique: string;
  name: string;
}

export interface Threat {
  id: string;
  ruleId: string;
  ruleName: string;
  severity: Severity;
  confidence: string;
  message: string;
  filePath: string;
  location: ThreatLocation;
  mitre?: MitreInfo;
  matchedStrings: string[];
  remediation?: {
    message: string;
    actions: string[];
  };
  tags?: string[];
}

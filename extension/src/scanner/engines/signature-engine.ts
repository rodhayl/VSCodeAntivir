import { DetectionRule } from '../models/rule';
import { executeRule } from '../../rules/rule-engine';
import { Threat } from '../models/threat';

export function runSignatureEngine(
  content: string,
  filePath: string,
  rules: DetectionRule[]
): Threat[] {
  const threats: Threat[] = [];
  for (const rule of rules) {
    const threat = executeRule(rule, content, filePath);
    if (threat) {
      threats.push(threat);
    }
  }
  return threats;
}

import { Severity, severityToString } from '../scanner/models/severity';
import { Threat } from '../scanner/models/threat';

export function escapeHtml(s: string): string {
  return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

export function getSecurityScore(threatMap: Map<string, Threat[]>): { score: number; bySeverity: Record<string, number> } {
  const allThreats: Threat[] = [];
  for (const threats of threatMap.values()) {
    allThreats.push(...threats);
  }

  const bySeverity: Record<string, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const t of allThreats) {
    bySeverity[severityToString(t.severity)]++;
  }

  const totalWeight = bySeverity.critical * 25 + bySeverity.high * 15 + bySeverity.medium * 8 + bySeverity.low * 3 + bySeverity.info * 1;
  const score = Math.max(0, 100 - totalWeight);

  return { score, bySeverity };
}

const TACTIC_ICONS: Record<string, string> = {
  'Initial Access': '🔓',
  'Execution': '⚡',
  'Persistence': '📌',
  'Defense Evasion': '🛡️',
  'Credential Access': '🔑',
  'Discovery': '🔍',
  'Collection': '📦',
  'Exfiltration': '📤',
  'Command and Control': '📡',
  'Other': '❓',
};

export function getTacticIcon(tactic: string): string {
  return TACTIC_ICONS[tactic] || '❓';
}

export function defangUrl(text: string): string {
  return text
    .replace(/https?:\/\//g, (m) => m.replace('http', 'hxxp'))
    .replace(/\./g, '[.]');
}

export function extractFileName(filePath: string): string {
  return filePath.split(/[/\\]/).pop() || filePath;
}

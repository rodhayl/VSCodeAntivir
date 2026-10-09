import { severityToString } from '../scanner/models/severity';
import { Threat } from '../scanner/models/threat';

export function escapeHtml(s: string): string {
  return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}

export function summarizeFindings(threatMap: Map<string, Threat[]>): { count: number; bySeverity: Record<string, number> } {
  const allThreats: Threat[] = [];
  for (const threats of threatMap.values()) {
    allThreats.push(...threats);
  }

  const bySeverity: Record<string, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const t of allThreats) {
    bySeverity[severityToString(t.severity)]++;
  }

  return { count: allThreats.length, bySeverity };
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

export function extractFileName(filePath: string): string {
  return filePath.split(/[/\\]/).pop() || filePath;
}

import { Threat, ThreatLocation } from '../models/threat';
import { Severity } from '../models/severity';
import { findHighEntropyStrings } from '../analyzers/entropy-analyzer';
import {
  countEvalUsage, countExecUsage, countHexStrings,
  countBase64Strings, detectStringArrayObfuscation,
} from '../analyzers/string-analyzer';

function loc(line: number, col: number): ThreatLocation {
  return { startLine: line, startCol: col, endLine: line, endCol: col + 10 };
}

function getLineCol(content: string, index: number): { line: number; col: number } {
  let line = 0, col = 0;
  for (let i = 0; i < Math.min(index, content.length); i++) {
    if (content[i] === '\n') { line++; col = 0; } else { col++; }
  }
  return { line, col };
}

export function runHeuristicEngine(content: string, filePath: string): Threat[] {
  const threats: Threat[] = [];
  const ext = filePath.split('.').pop()?.toLowerCase() || '';
  const isCode = ['js', 'mjs', 'ts', 'py', 'ps1', 'sh'].includes(ext);
  if (!isCode) return threats;

  // 1. Eval/exec density
  const evalCount = countEvalUsage(content);
  const execCount = countExecUsage(content);
  if (evalCount >= 2) {
    const idx = content.indexOf('eval');
    const { line, col } = getLineCol(content, idx >= 0 ? idx : 0);
    threats.push({
      id: `heuristic-eval-density-${Date.now()}`,
      ruleId: 'heuristic-eval-density',
      ruleName: 'High eval() Usage',
      severity: Severity.MEDIUM,
      confidence: 'medium',
      message: `File contains ${evalCount} eval() calls — common in obfuscated malware`,
      filePath,
      location: loc(line, col),
      matchedStrings: [`${evalCount} eval() calls found`],
    });
  }
  if (execCount >= 5) {
    threats.push({
      id: `heuristic-exec-density-${Date.now()}`,
      ruleId: 'heuristic-exec-density',
      ruleName: 'High exec/spawn Usage',
      severity: Severity.MEDIUM,
      confidence: 'medium',
      message: `File contains ${execCount} process execution calls`,
      filePath,
      location: loc(0, 0),
      matchedStrings: [`${execCount} exec/spawn calls found`],
    });
  }

  // 2. Hex/Base64 encoded payloads
  const hexCount = countHexStrings(content);
  const b64Count = countBase64Strings(content);
  if (hexCount >= 2) {
    threats.push({
      id: `heuristic-hex-payload-${Date.now()}`,
      ruleId: 'heuristic-hex-payload',
      ruleName: 'Hex-encoded Payload Detected',
      severity: Severity.LOW,
      confidence: 'low',
      message: `File contains ${hexCount} long hex-encoded string(s) — may indicate encoded payload`,
      filePath,
      location: loc(0, 0),
      matchedStrings: [`${hexCount} hex strings >40 chars`],
    });
  }
  if (b64Count >= 2) {
    threats.push({
      id: `heuristic-b64-payload-${Date.now()}`,
      ruleId: 'heuristic-b64-payload',
      ruleName: 'Base64-encoded Payload Detected',
      severity: Severity.LOW,
      confidence: 'low',
      message: `File contains ${b64Count} long base64-encoded string(s)`,
      filePath,
      location: loc(0, 0),
      matchedStrings: [`${b64Count} base64 strings >40 chars`],
    });
  }

  // 3. String array obfuscation
  if (detectStringArrayObfuscation(content)) {
    threats.push({
      id: `heuristic-string-obfuscation-${Date.now()}`,
      ruleId: 'heuristic-string-obfuscation',
      ruleName: 'String Array Obfuscation Pattern',
      severity: Severity.MEDIUM,
      confidence: 'medium',
      message: 'File uses a large string array pattern — common in obfuscated malware like OtterCookie v2',
      filePath,
      location: loc(0, 0),
      matchedStrings: ['Large string array with 15+ elements detected'],
    });
  }

  // 4. High entropy strings
  const highEntropy = findHighEntropyStrings(content, 5.5, 50);
  if (highEntropy.length >= 3) {
    const { line, col } = getLineCol(content, highEntropy[0].index);
    threats.push({
      id: `heuristic-high-entropy-${Date.now()}`,
      ruleId: 'heuristic-high-entropy',
      ruleName: 'Multiple High-Entropy Strings',
      severity: Severity.LOW,
      confidence: 'low',
      message: `File contains ${highEntropy.length} high-entropy strings — may indicate encoded/encrypted content`,
      filePath,
      location: loc(line, col),
      matchedStrings: highEntropy.slice(0, 3).map(h => `entropy=${h.entropy.toFixed(2)}: "${h.value.substring(0, 30)}..."`),
    });
  }

  return threats;
}

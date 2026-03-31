import * as fs from 'fs';
import * as path from 'path';
import { Threat, ThreatLocation } from '../models/threat';
import { Severity } from '../models/severity';
import { checkTyposquat } from '../analyzers/typosquat-analyzer';

function loc(line: number, col: number, endCol?: number): ThreatLocation {
  return { startLine: line, startCol: col, endLine: line, endCol: endCol || col + 10 };
}

function findLineOfKey(content: string, key: string): number {
  const lines = content.split('\n');
  for (let i = 0; i < lines.length; i++) {
    if (lines[i].includes(`"${key}"`)) return i;
  }
  return 0;
}

export function runNpmAuditEngine(content: string, filePath: string): Threat[] {
  const threats: Threat[] = [];
  const fileName = path.basename(filePath);
  if (fileName !== 'package.json') return threats;

  let pkg: any;
  try {
    pkg = JSON.parse(content);
  } catch {
    return threats;
  }

  const scripts = pkg.scripts || {};

  // 1. Suspicious preinstall/postinstall scripts
  const dangerousScripts = ['preinstall', 'postinstall', 'prestart'];
  for (const scriptName of dangerousScripts) {
    const scriptVal = scripts[scriptName];
    if (!scriptVal) continue;

    const suspiciousIndicators = [
      'node ', 'curl ', 'wget ', 'sh ', 'bash ', 'cmd ', 'powershell',
      'eval', 'exec', 'http://', 'https://',
    ];
    const isSuspicious = suspiciousIndicators.some(ind => scriptVal.toLowerCase().includes(ind));
    if (isSuspicious) {
      const line = findLineOfKey(content, scriptName);
      threats.push({
        id: `npm-suspicious-script-${scriptName}-${Date.now()}`,
        ruleId: 'npm-suspicious-script',
        ruleName: `Suspicious ${scriptName} Script`,
        severity: Severity.HIGH,
        confidence: 'high',
        message: `package.json has a suspicious "${scriptName}" script: "${scriptVal.substring(0, 80)}"`,
        filePath,
        location: loc(line, 0, scriptVal.length),
        mitre: { tactic: 'Execution', technique: 'T1059.007', name: 'JavaScript' },
        matchedStrings: [scriptVal],
        remediation: {
          message: `Remove or review the "${scriptName}" script in package.json`,
          actions: ['remove-hook'],
        },
      });
    }
  }

  // 2. Typosquatting in dependencies
  const allDeps = { ...(pkg.dependencies || {}), ...(pkg.devDependencies || {}) };
  for (const [depName] of Object.entries(allDeps)) {
    const typoCheck = checkTyposquat(depName);
    if (typoCheck.isSuspicious) {
      const line = findLineOfKey(content, depName);
      threats.push({
        id: `npm-typosquat-${depName}-${Date.now()}`,
        ruleId: 'npm-typosquat',
        ruleName: 'Potential Typosquatting Package',
        severity: Severity.MEDIUM,
        confidence: 'medium',
        message: `Package "${depName}" is suspiciously similar to "${typoCheck.similarTo}" (distance: ${typoCheck.distance})`,
        filePath,
        location: loc(line, 0),
        matchedStrings: [depName, typoCheck.similarTo || ''],
      });
    }
  }

  // 3. Scripts pointing to suspicious JS files
  const suspiciousScriptFiles = ['setup_bun', 'bun_environment', 'setup_', 'install.js'];
  for (const [, val] of Object.entries(scripts) as [string, string][]) {
    for (const susFile of suspiciousScriptFiles) {
      if (val.includes(susFile)) {
        const line = findLineOfKey(content, val);
        threats.push({
          id: `npm-suspicious-file-ref-${Date.now()}`,
          ruleId: 'npm-suspicious-file-ref',
          ruleName: 'Script References Suspicious File',
          severity: Severity.MEDIUM,
          confidence: 'medium',
          message: `Script references suspicious file pattern: "${susFile}"`,
          filePath,
          location: loc(line, 0),
          matchedStrings: [val],
        });
        break;
      }
    }
  }

  return threats;
}

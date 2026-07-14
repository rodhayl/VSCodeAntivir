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

interface KnownBadPackage {
  name: string;
  versions?: string[];
  allVersions?: boolean;
  severity: 'critical' | 'high';
  campaign: string;
  description: string;
  cve?: string;
}

const KNOWN_BAD_PACKAGES: KnownBadPackage[] = [
  // March 2026 - Axios/BlueNoroff supply chain compromise
  {
    name: 'plain-crypto-js',
    allVersions: true,
    severity: 'critical',
    campaign: 'BlueNoroff/UNC1069',
    description: 'Fake cryptography package from Axios compromise. Installs macOS RAT.'
  },
  {
    name: 'axios',
    versions: ['1.14.1', '0.30.4'],
    severity: 'critical',
    campaign: 'BlueNoroff/UNC1069',
    description: 'Compromised versions install plain-crypto-js backdoor. Affects 100M+ downloads.',
    cve: 'CVE-2026-XXXX'
  },
  // TeamPCP Campaign - Typosquatted packages
  {
    name: 'trvy',
    allVersions: true,
    severity: 'critical',
    campaign: 'TeamPCP',
    description: 'Typosquatted Trivy. Steals CI/CD credentials and installs CanisterWorm.'
  },
  {
    name: 'litellm-js',
    allVersions: true,
    severity: 'critical',
    campaign: 'TeamPCP',
    description: 'Typosquatted LiteLLM. Contains steganographic payload.'
  },
  {
    name: 'telnyx-sdk',
    allVersions: true,
    severity: 'critical',
    campaign: 'TeamPCP',
    description: 'Typosquatted Telnyx. Downloads WAV files with encoded malware.'
  },
  // Contagious Interview - Known packages
  {
    name: 'beavertail',
    allVersions: true,
    severity: 'critical',
    campaign: 'Contagious Interview',
    description: 'Known DPRK malware package. Browser credential stealer.'
  },
  {
    name: 'invisibleferret',
    allVersions: true,
    severity: 'critical',
    campaign: 'Contagious Interview',
    description: 'Known DPRK backdoor. Full remote access trojan.'
  },
  {
    name: 'ottercookie',
    allVersions: true,
    severity: 'critical',
    campaign: 'Contagious Interview',
    description: 'Known DPRK cookie stealer variant.'
  },
  // General malicious packages
  {
    name: 'event-stream',
    versions: ['3.3.6'],
    severity: 'critical',
    campaign: 'Cryptocurrency Theft',
    description: 'Version 3.3.6 contains flatmap-stream backdoor targeting Bitcoin wallets.',
    cve: 'CVE-2018-16487'
  },
  {
    name: 'ua-parser-js',
    versions: ['0.7.29', '0.8.0', '1.0.0'],
    severity: 'critical',
    campaign: 'Cryptominer/Password Stealer',
    description: 'Hijacked versions install cryptominer and password stealer.',
    cve: 'CVE-2021-41266'
  },
  {
    name: 'coa',
    versions: ['2.0.3', '2.0.4', '2.1.1', '2.1.3', '3.0.1', '3.1.3'],
    severity: 'critical',
    campaign: 'Supply Chain Compromise',
    description: 'Compromised versions install credential stealers.',
    cve: 'CVE-2021-44906'
  },
  {
    name: 'rc',
    versions: ['1.2.9', '1.3.9', '2.3.9'],
    severity: 'critical',
    campaign: 'Supply Chain Compromise',
    description: 'Compromised versions alongside coa attack.'
  },
  // April 2026 - TeamPCP/Cisco breach
  {
    name: 'trivy-action',
    allVersions: true,
    severity: 'critical',
    campaign: 'TeamPCP/Cisco Breach',
    description: 'GitHub Action compromised in March 2026 to steal CI/CD credentials.'
  },
  {
    name: 'checkmarx-kics',
    allVersions: true,
    severity: 'critical',
    campaign: 'TeamPCP/Cisco Breach',
    description: 'KICS action compromised to deploy credential stealers.'
  },
  // Silver Fox campaign - March 2026
  {
    name: 'surfshark-vpn',
    allVersions: true,
    severity: 'critical',
    campaign: 'Silver Fox/AtlasCross',
    description: 'Typosquatted Surfshark VPN package delivering AtlasCross RAT.'
  },
  {
    name: 'signal-desktop-app',
    allVersions: true,
    severity: 'critical',
    campaign: 'Silver Fox/AtlasCross',
    description: 'Typosquatted Signal package delivering AtlasCross RAT.'
  },
  {
    name: 'telegram-desktop-app',
    allVersions: true,
    severity: 'critical',
    campaign: 'Silver Fox/AtlasCross',
    description: 'Typosquatted Telegram package delivering AtlasCross RAT.'
  },
  // 2026 developer-targeted supply-chain campaigns
  {
    name: 'redeem-onchain-sdk',
    allVersions: true,
    severity: 'critical',
    campaign: 'UNK_DeadDrop',
    description: 'Malicious SDK observed in wallet- and developer-targeting supply-chain campaigns.'
  },
  {
    name: 'period-newline',
    allVersions: true,
    severity: 'critical',
    campaign: 'UNK_DeadDrop',
    description: 'Malicious npm package linked to recent developer-targeted malware delivery.'
  },
  {
    name: 'html-to-gutenberg',
    allVersions: true,
    severity: 'critical',
    campaign: 'TaskJacker',
    description: 'Trojanized package reported abusing VS Code task execution to stage payloads.'
  },
  {
    name: 'fetch-page-assets',
    allVersions: true,
    severity: 'critical',
    campaign: 'TaskJacker',
    description: 'Trojanized package reported using malicious VS Code tasks and downloader logic.'
  },
];

function matchesVersion(installedVersion: string, badVersions: string[]): boolean {
  const cleanVersion = installedVersion.replace(/[\^~>=<]/g, '').trim();
  return badVersions.some(v => cleanVersion === v || cleanVersion.startsWith(v + '.'));
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
  const allDeps = { ...(pkg.dependencies || {}), ...(pkg.devDependencies || {}) };

  // 1. Check for known-bad packages (CRITICAL - blocks active attacks)
  for (const [depName, depVersion] of Object.entries(allDeps) as [string, string][]) {
    const badPkg = KNOWN_BAD_PACKAGES.find(p => p.name === depName.toLowerCase());
    if (badPkg) {
      const isVulnerable = badPkg.allVersions || 
        (badPkg.versions && matchesVersion(depVersion, badPkg.versions));
      
      if (isVulnerable) {
        const line = findLineOfKey(content, depName);
        threats.push({
          id: `npm-known-bad-${depName}-${Date.now()}`,
          ruleId: 'npm-known-bad-package',
          ruleName: `Known Malicious Package: ${depName}`,
          severity: badPkg.severity === 'critical' ? Severity.CRITICAL : Severity.HIGH,
          confidence: 'high',
          message: `⚠️ BLOCKED: "${depName}@${depVersion}" is a known malicious package. ` +
            `Campaign: ${badPkg.campaign}. ${badPkg.description}`,
          filePath,
          location: loc(line, 0, depVersion.length + depName.length),
          mitre: { tactic: 'Initial Access', technique: 'T1195.002', name: 'Supply Chain Compromise' },
          matchedStrings: [depName, depVersion],
          remediation: {
            message: `IMMEDIATELY remove "${depName}" from package.json and run npm uninstall ${depName}`,
            actions: ['remove-dependency', 'quarantine'],
          },
          tags: ['supply-chain', 'known-malware', badPkg.campaign.toLowerCase().replace(/\s+/g, '-')],
        });
      }
    }
  }

  // 2. Suspicious preinstall/postinstall scripts
  const dangerousScripts = ['preinstall', 'postinstall', 'prestart'];
  for (const scriptName of dangerousScripts) {
    const scriptVal = scripts[scriptName];
    if (!scriptVal) continue;

    const suspiciousIndicators = [
      'node ', 'curl ', 'wget ', 'sh ', 'bash ', 'cmd ', 'powershell',
      'eval', 'exec', 'http://', 'https://', '--install-extension',
      'code --install-extension', 'cursor --install-extension', 'windsurf --install-extension',
      'codium --install-extension', 'openvsx', 'solana', 'base64 -d',
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

  // 3. Typosquatting in dependencies
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

  // 4. Scripts pointing to suspicious JS files
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

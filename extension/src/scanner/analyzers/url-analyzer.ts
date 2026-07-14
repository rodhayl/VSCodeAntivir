const SUSPICIOUS_DOMAINS = [
  'vercel.app', 'short.gy', 'bit.ly', 't.co', 'tinyurl.com',
  'is.gd', 'rb.gy', 'cutt.ly',
];

const SUSPICIOUS_PATTERNS = [
  /\|\s*sh\b/,
  /\|\s*bash\b/,
  /\|\s*cmd\b/,
  /\|\s*powershell\b/,
  /curl\s+[^|]*\|/,
  /wget\s+[^|]*\|/,
  /Invoke-WebRequest/i,
  /Invoke-Expression/i,
  /iex\s*\(/i,
];

export interface UrlFinding {
  url: string;
  index: number;
  reason: string;
}

/** Extract all URLs from content. Used by findSuspiciousUrls. */
export function extractUrls(content: string): Array<{ url: string; index: number }> {
  const urlPattern = /https?:\/\/[^\s"'`<>)\]},]+/g;
  const results: Array<{ url: string; index: number }> = [];
  let match;
  while ((match = urlPattern.exec(content)) !== null) {
    results.push({ url: match[0], index: match.index });
  }
  return results;
}

/** Find URLs pointing to suspicious domains or raw IPs. For heuristic engine future use. */
export function findSuspiciousUrls(content: string): UrlFinding[] {
  const urls = extractUrls(content);
  const findings: UrlFinding[] = [];
  for (const { url, index } of urls) {
    for (const domain of SUSPICIOUS_DOMAINS) {
      if (url.includes(domain)) {
        findings.push({ url, index, reason: `URL contains suspicious domain: ${domain}` });
      }
    }
    const ipMatch = url.match(/https?:\/\/(\d+\.\d+\.\d+\.\d+)/);
    if (ipMatch && ipMatch[1] !== '127.0.0.1' && ipMatch[1] !== '0.0.0.0') {
      findings.push({ url, index, reason: `URL contains IP address: ${ipMatch[1]}` });
    }
  }
  return findings;
}

/** Find piped execution patterns (curl | sh). For heuristic engine future use. */
export function findPipedExecution(content: string): Array<{ pattern: string; index: number }> {
  const results: Array<{ pattern: string; index: number }> = [];
  for (const pattern of SUSPICIOUS_PATTERNS) {
    const globalPattern = new RegExp(pattern.source, pattern.flags + (pattern.flags.includes('g') ? '' : 'g'));
    let match;
    while ((match = globalPattern.exec(content)) !== null) {
      results.push({ pattern: match[0], index: match.index });
    }
  }
  return results;
}

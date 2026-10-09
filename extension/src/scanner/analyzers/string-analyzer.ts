

export function countHexStrings(content: string, minLen: number = 40): number {
  const hexPattern = /(?:0x)?[0-9a-fA-F]{40,}/g;
  let count = 0;
  let match;
  while ((match = hexPattern.exec(content)) !== null) {
    if (match[0].length >= minLen) count++;
  }
  return count;
}

export function countBase64Strings(content: string, minLen: number = 40): number {
  const b64Pattern = /[A-Za-z0-9+/]{40,}={0,2}/g;
  let count = 0;
  let match;
  while ((match = b64Pattern.exec(content)) !== null) {
    if (match[0].length >= minLen) count++;
  }
  return count;
}

export function countEvalUsage(content: string): number {
  const evalPattern = /\beval\s*\(/g;
  let count = 0;
  while (evalPattern.exec(content) !== null) count++;
  return count;
}

export function countExecUsage(content: string): number {
  const patterns = [
    /\bexec\s*\(/g,
    /\bexecSync\s*\(/g,
    /\bspawn\s*\(/g,
    /\bspawnSync\s*\(/g,
    /child_process/g,
    /subprocess\.Popen/g,
    /os\.system\s*\(/g,
  ];
  let count = 0;
  for (const p of patterns) {
    while (p.exec(content) !== null) count++;
  }
  return count;
}

export function detectStringArrayObfuscation(content: string): boolean {
  // Detect pattern: large string array followed by index-based access
  const arrayPattern = /\[\s*(?:["'][^"']*["']\s*,\s*){15,}/;
  return arrayPattern.test(content);
}

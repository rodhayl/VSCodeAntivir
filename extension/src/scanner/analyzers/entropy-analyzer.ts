export function shannonEntropy(s: string): number {
  if (s.length === 0) return 0;
  const freq: Record<string, number> = {};
  for (const c of s) {
    freq[c] = (freq[c] || 0) + 1;
  }
  let entropy = 0;
  const len = s.length;
  for (const count of Object.values(freq)) {
    const p = count / len;
    if (p > 0) entropy -= p * Math.log2(p);
  }
  return entropy;
}

export function findHighEntropyStrings(
  content: string,
  threshold: number,
  minLength: number
): Array<{ value: string; entropy: number; index: number }> {
  const results: Array<{ value: string; entropy: number; index: number }> = [];
  // Match string literals (single, double, backtick)
  const stringPattern = /(?:"([^"\\]*(?:\\.[^"\\]*)*)"|'([^'\\]*(?:\\.[^'\\]*)*)'|`([^`\\]*(?:\\.[^`\\]*)*)`)/g;
  let match;
  while ((match = stringPattern.exec(content)) !== null) {
    const value = match[1] ?? match[2] ?? match[3] ?? '';
    if (value.length >= minLength) {
      const ent = shannonEntropy(value);
      if (ent >= threshold) {
        results.push({ value: value.substring(0, 80), entropy: ent, index: match.index });
      }
    }
  }
  return results;
}

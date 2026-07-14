import * as crypto from 'crypto';
import { LlmAnalysisResult } from './models';

export class LlmCache {
  private cache = new Map<string, { result: LlmAnalysisResult; timestamp: number }>();
  private maxEntries: number;
  private ttlMs: number;

  constructor(maxEntries = 50, ttlMinutes = 60) {
    this.maxEntries = maxEntries;
    this.ttlMs = ttlMinutes * 60 * 1000;
  }

  private makeKey(content: string, promptProfile: string): string {
    return crypto.createHash('sha256')
      .update(promptProfile + '\0' + content)
      .digest('hex')
      .substring(0, 16);
  }

  get(content: string, promptProfile: string): LlmAnalysisResult | null {
    const key = this.makeKey(content, promptProfile);
    const entry = this.cache.get(key);
    if (!entry) return null;
    if (Date.now() - entry.timestamp > this.ttlMs) {
      this.cache.delete(key);
      return null;
    }
    return { ...entry.result, fromCache: true };
  }

  set(content: string, promptProfile: string, result: LlmAnalysisResult): void {
    const key = this.makeKey(content, promptProfile);
    if (this.cache.size >= this.maxEntries) {
      const now = Date.now();
      for (const [k, entry] of this.cache) {
        if (now - entry.timestamp > this.ttlMs) {
          this.cache.delete(k);
        }
      }
      if (this.cache.size >= this.maxEntries) {
        const oldestKey = this.cache.keys().next().value;
        if (oldestKey) this.cache.delete(oldestKey);
      }
    }
    this.cache.set(key, { result: { ...result }, timestamp: Date.now() });
  }

  clear(): void {
    this.cache.clear();
  }

  get size(): number {
    return this.cache.size;
  }
}

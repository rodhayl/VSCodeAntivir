import * as fs from 'fs';
import * as path from 'path';
import { PromptTemplate } from './models';

export class PromptBuilder {
  private templates = new Map<string, PromptTemplate>();

  loadTemplatesFromDirectory(dir: string): void {
    if (!fs.existsSync(dir)) return;
    this.loadRecursive(dir);
  }

  private loadRecursive(dir: string): void {
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      const fullPath = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        this.loadRecursive(fullPath);
      } else if (entry.name.endsWith('.prompt.md')) {
        try {
          const template = this.parseTemplate(fs.readFileSync(fullPath, 'utf-8'));
          if (template) this.templates.set(template.name, template);
        } catch { /* skip invalid */ }
      }
    }
  }

  private parseTemplate(content: string): PromptTemplate | null {
    const fmMatch = content.match(/^---\r?\n([\s\S]*?)\r?\n---\r?\n([\s\S]*)$/);
    if (!fmMatch) return null;

    const meta: Record<string, string> = {};
    for (const line of fmMatch[1].split(/\r?\n/)) {
      const idx = line.indexOf(':');
      if (idx > 0) {
        meta[line.substring(0, idx).trim()] = line.substring(idx + 1).trim();
      }
    }

    const body = fmMatch[2];
    const systemMatch = body.match(/## System\r?\n([\s\S]*?)(?=\r?\n## )/);
    const userMatch = body.match(/## User\r?\n([\s\S]*?)$/);
    if (!systemMatch || !userMatch) return null;

    return {
      name: meta.name || 'unnamed',
      maxTokens: parseInt(meta.max_tokens || '1024', 10),
      temperature: parseFloat(meta.temperature || '0.1'),
      systemPrompt: systemMatch[1].trim(),
      userTemplate: userMatch[1].trim(),
    };
  }

  buildPrompt(
    templateName: string,
    variables: Record<string, string>
  ): { systemPrompt: string; userPrompt: string; maxTokens: number; temperature: number } | null {
    const template = this.templates.get(templateName);
    if (!template) return null;

    let systemPrompt = template.systemPrompt;
    let userPrompt = template.userTemplate;

    for (const [key, value] of Object.entries(variables)) {
      const escaped = `{{${key}}}`.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
      const re = new RegExp(escaped, 'g');
      systemPrompt = systemPrompt.replace(re, value);
      userPrompt = userPrompt.replace(re, value);
    }

    return {
      systemPrompt,
      userPrompt,
      maxTokens: template.maxTokens,
      temperature: template.temperature,
    };
  }

  truncateCode(code: string, maxTokens: number = 6000): string {
    const maxChars = Math.floor(maxTokens * 3.5);
    if (code.length <= maxChars) return code;
    return code.substring(0, maxChars) + '\n// ... [truncated for LLM analysis]';
  }

  getTemplateNames(): string[] {
    return [...this.templates.keys()];
  }

  hasTemplate(name: string): boolean {
    return this.templates.has(name);
  }
}

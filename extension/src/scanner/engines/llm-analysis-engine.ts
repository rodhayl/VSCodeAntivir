import * as path from 'path';
import { Threat } from '../models/threat';
import { LlmClient } from '../../llm/llm-client';
import { LlmCache } from '../../llm/llm-cache';
import { PromptBuilder } from '../../llm/prompt-builder';
import { ResponseParser } from '../../llm/response-parser';
import { LlmAnalysisResult } from '../../llm/models';

export class LlmAnalysisEngine {
  private client: LlmClient;
  private cache: LlmCache;
  private promptBuilder: PromptBuilder;
  private responseParser: ResponseParser;
  private promptProfile: string;

  constructor(
    client: LlmClient,
    cache: LlmCache,
    promptBuilder: PromptBuilder,
    promptProfile: string = 'Security Analysis'
  ) {
    this.client = client;
    this.cache = cache;
    this.promptBuilder = promptBuilder;
    this.responseParser = new ResponseParser();
    this.promptProfile = promptProfile;
  }

  async analyzeFile(
    filePath: string,
    content: string,
    options?: { promptOverride?: string }
  ): Promise<{ threats: Threat[]; result: LlmAnalysisResult }> {
    const templateName = options?.promptOverride || this.promptProfile;

    // Check cache
    const cached = this.cache.get(content, templateName);
    if (cached) {
      const threats = this.responseParser.mapToThreats(cached, filePath, content);
      return { threats, result: cached };
    }

    // Determine language from extension
    const ext = path.extname(filePath).toLowerCase();
    const langMap: Record<string, string> = {
      '.js': 'javascript', '.mjs': 'javascript', '.ts': 'typescript',
      '.py': 'python', '.ps1': 'powershell', '.sh': 'bash', '.json': 'json',
    };
    const language = langMap[ext] || 'text';

    // Truncate code for token budget
    const truncatedCode = this.promptBuilder.truncateCode(content);

    // Build prompt
    const prompt = this.promptBuilder.buildPrompt(templateName, {
      code: truncatedCode,
      filename: path.basename(filePath),
      language,
    });

    if (!prompt) {
      // Fall back to the default Security Analysis template
      const fallback = this.promptBuilder.buildPrompt('Security Analysis', {
        code: truncatedCode,
        filename: path.basename(filePath),
        language,
      });
      if (!fallback) {
        throw new Error(`No prompt template found: "${templateName}" or "Security Analysis"`);
      }
      return this.executeAnalysis(fallback, filePath, content, templateName);
    }

    return this.executeAnalysis(prompt, filePath, content, templateName);
  }

  private async executeAnalysis(
    prompt: { systemPrompt: string; userPrompt: string; maxTokens: number; temperature: number },
    filePath: string,
    content: string,
    cacheKey: string
  ): Promise<{ threats: Threat[]; result: LlmAnalysisResult }> {
    const start = Date.now();

    const response = await this.client.chat(prompt.systemPrompt, prompt.userPrompt, {
      maxTokens: prompt.maxTokens,
      temperature: prompt.temperature,
    });

    const durationMs = Date.now() - start;
    const result = this.responseParser.parseAnalysisResponse(response.content, response.model, durationMs);

    // Cache the result
    this.cache.set(content, cacheKey, result);

    const threats = this.responseParser.mapToThreats(result, filePath, content);
    return { threats, result };
  }

  async explainThreat(
    filePath: string,
    ruleName: string,
    description: string,
    evidence: string
  ): Promise<string> {
    const prompt = this.promptBuilder.buildPrompt('Explain Threat', {
      filename: path.basename(filePath),
      rule_name: ruleName,
      description,
      evidence,
    });

    if (!prompt) {
      throw new Error('Explain Threat prompt template not found');
    }

    const response = await this.client.chat(prompt.systemPrompt, prompt.userPrompt, {
      maxTokens: prompt.maxTokens,
      temperature: prompt.temperature,
    });

    // Try to parse the JSON explanation
    try {
      const json = JSON.parse(response.content);
      return [
        `## ${ruleName}`,
        '',
        `**Risk Level:** ${json.risk_level || 'unknown'}`,
        '',
        `### Explanation`,
        json.explanation || 'No explanation available.',
        '',
        `### Attack Chain`,
        json.attack_chain || 'N/A',
        '',
        `### Mitigation`,
        json.mitigation || 'Review and remove the suspicious code.',
      ].join('\n');
    } catch {
      return response.content;
    }
  }

  async suggestRule(filePath: string, content: string): Promise<string> {
    const ext = path.extname(filePath).toLowerCase();
    const langMap: Record<string, string> = {
      '.js': 'javascript', '.mjs': 'javascript', '.ts': 'typescript',
      '.py': 'python', '.ps1': 'powershell', '.sh': 'bash', '.json': 'json',
    };
    const language = langMap[ext] || 'text';

    const prompt = this.promptBuilder.buildPrompt('Suggest Rule', {
      code: this.promptBuilder.truncateCode(content, 3000),
      filename: path.basename(filePath),
      language,
    });

    if (!prompt) {
      throw new Error('Suggest Rule prompt template not found');
    }

    const response = await this.client.chat(prompt.systemPrompt, prompt.userPrompt, {
      maxTokens: prompt.maxTokens,
      temperature: prompt.temperature,
    });

    // Try to format the JSON nicely
    try {
      const json = JSON.parse(response.content);
      return JSON.stringify(json, null, 2);
    } catch {
      // Try to extract JSON from the response
      const match = response.content.match(/\{[\s\S]*\}/);
      if (match) {
        try {
          return JSON.stringify(JSON.parse(match[0]), null, 2);
        } catch {}
      }
      return response.content;
    }
  }
}

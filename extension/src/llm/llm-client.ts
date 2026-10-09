import OpenAI from 'openai';
import { LlmConfig, PROVIDER_DEFAULTS } from './models';

export class LlmClient {
  private client: OpenAI;
  private config: LlmConfig;

  constructor(config: LlmConfig) {
    this.config = config;
    const defaults = PROVIDER_DEFAULTS[config.provider] || PROVIDER_DEFAULTS.custom;
    const baseURL = config.baseUrl || defaults.baseUrl;
    const endpoint = new URL(baseURL);
    if (!['http:', 'https:'].includes(endpoint.protocol) || endpoint.username || endpoint.password) {
      throw new Error('Use an HTTP(S) model endpoint without embedded credentials');
    }
    this.client = new OpenAI({
      baseURL,
      apiKey: config.apiKey || defaults.apiKey || 'no-key',
      timeout: config.timeout,
      maxRetries: 1,
    });
  }

  async chat(
    systemPrompt: string,
    userPrompt: string,
    options?: { maxTokens?: number; temperature?: number; signal?: AbortSignal }
  ): Promise<{ content: string; model: string; promptTokens: number; completionTokens: number }> {
    const response = await this.client.chat.completions.create({
      model: this.config.model,
      messages: [
        { role: 'system' as const, content: systemPrompt },
        { role: 'user' as const, content: userPrompt },
      ],
      max_tokens: options?.maxTokens ?? this.config.maxTokens,
      temperature: options?.temperature ?? this.config.temperature,
    }, { signal: options?.signal });

    return {
      content: response.choices[0]?.message?.content || '',
      model: response.model || this.config.model,
      promptTokens: response.usage?.prompt_tokens || 0,
      completionTokens: response.usage?.completion_tokens || 0,
    };
  }

  async checkHealth(): Promise<{ ok: boolean; models: string[]; error?: string }> {
    try {
      const response = await this.client.models.list();
      const modelsArray: string[] = [];
      const modelsList = response as unknown as { data: Array<{ id: string }> };
      if (Array.isArray(modelsList.data)) {
        for (const m of modelsList.data) {
          modelsArray.push(m.id);
        }
      }
      return { ok: true, models: modelsArray };
    } catch (e: unknown) {
      return { ok: false, models: [], error: e instanceof Error ? e.message : String(e) };
    }
  }

  getConfig(): LlmConfig {
    return { ...this.config };
  }
}

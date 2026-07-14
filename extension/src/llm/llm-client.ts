import OpenAI from 'openai';
import { LlmConfig, PROVIDER_DEFAULTS } from './models';

export class LlmClient {
  private client: OpenAI;
  private config: LlmConfig;

  constructor(config: LlmConfig) {
    this.config = config;
    const defaults = PROVIDER_DEFAULTS[config.provider] || PROVIDER_DEFAULTS.custom;
    this.client = new OpenAI({
      baseURL: config.baseUrl || defaults.baseUrl,
      apiKey: config.apiKey || defaults.apiKey || 'no-key',
      timeout: config.timeout,
      maxRetries: 1,
    });
  }

  async chat(
    systemPrompt: string,
    userPrompt: string,
    options?: { maxTokens?: number; temperature?: number }
  ): Promise<{ content: string; model: string; promptTokens: number; completionTokens: number }> {
    const response = await this.client.chat.completions.create({
      model: this.config.model,
      messages: [
        { role: 'system' as const, content: systemPrompt },
        { role: 'user' as const, content: userPrompt },
      ],
      max_tokens: options?.maxTokens ?? this.config.maxTokens,
      temperature: options?.temperature ?? this.config.temperature,
    });

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
    } catch (e: any) {
      return { ok: false, models: [], error: e.message };
    }
  }

  getConfig(): LlmConfig {
    return { ...this.config };
  }
}

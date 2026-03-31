import { Severity } from '../scanner/models/severity';

export interface LlmConfig {
  enabled: boolean;
  provider: string;
  baseUrl: string;
  model: string;
  apiKey: string;
  maxTokens: number;
  temperature: number;
  autoAnalyze: boolean;
  timeout: number;
  promptProfile: string;
}

export interface LlmFinding {
  type: string;
  severity: string;
  evidence: string;
  line?: number | null;
  recommendation?: string;
}

export interface LlmAnalysisResult {
  malicious: boolean;
  confidence: number;
  threats: LlmFinding[];
  summary: string;
  campaignMatch?: string;
  malwareFamily?: string;
  rawResponse: string;
  model: string;
  durationMs: number;
  fromCache: boolean;
}

export interface PromptTemplate {
  name: string;
  maxTokens: number;
  temperature: number;
  systemPrompt: string;
  userTemplate: string;
}

export const PROVIDER_DEFAULTS: Record<string, { baseUrl: string; apiKey: string }> = {
  lmstudio: { baseUrl: 'http://localhost:1234/v1', apiKey: 'lm-studio' },
  ollama: { baseUrl: 'http://localhost:11434/v1', apiKey: 'ollama' },
  openai: { baseUrl: 'https://api.openai.com/v1', apiKey: '' },
  custom: { baseUrl: '', apiKey: '' },
};

export function readLlmConfig(getConfig: (key: string) => any): LlmConfig {
  return {
    enabled: getConfig('fig.llm.enabled') ?? false,
    provider: getConfig('fig.llm.provider') ?? 'lmstudio',
    baseUrl: getConfig('fig.llm.baseUrl') ?? '',
    model: getConfig('fig.llm.model') ?? 'qwen3.5-4b',
    apiKey: getConfig('fig.llm.apiKey') ?? '',
    maxTokens: getConfig('fig.llm.maxTokens') ?? 1024,
    temperature: getConfig('fig.llm.temperature') ?? 0.1,
    autoAnalyze: getConfig('fig.llm.autoAnalyze') ?? false,
    timeout: getConfig('fig.llm.timeout') ?? 60000,
    promptProfile: getConfig('fig.llm.promptProfile') ?? 'default',
  };
}

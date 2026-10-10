// Inert strings and stub model transport only. No live requests or fixture execution.
const assert = require('assert');
const fs = require('fs');
const path = require('path');
const os = require('os');
const { PromptBuilder } = require('../../out/llm/prompt-builder');
const { LlmCache } = require('../../out/llm/llm-cache');
const { LlmAnalysisEngine } = require('../../out/scanner/engines/llm-analysis-engine');
const { createHost, modelResponse, tick } = require('../helpers/extension-host-stub');
const literal = '$& $` $\' $$ {{filename}} {{language}} {{code}} {{evidence}} ` á 🛡️\r\n';
function builder() { const b = new PromptBuilder(); b.loadTemplatesFromDirectory(path.resolve(__dirname, '../../prompts')); return b; }
function engineFixture() {
  const calls = [], cache = new LlmCache(), b = builder();
  const client = { async chat(systemPrompt, userPrompt, options) { calls.push({ systemPrompt, userPrompt, options }); return { content: JSON.stringify({malicious:false, threats:[], summary:`response ${calls.length}`}), model:'stub' }; } };
  return { calls, cache, builder:b, engine:new LlmAnalysisEngine(client, cache, b) };
}
suite('R2 literal single-pass prompt interpolation', () => {
  test('all bundled templates preserve placeholder-shaped and replacement-token values', () => {
    const b = builder(), variables = Object.fromEntries(['code','filename','language','rule_name','description','evidence'].map(key => [key, literal + key]));
    for (const name of b.getTemplateNames()) {
      const template = b.templates.get(name), actual = b.buildPrompt(name, variables);
      for (const [source, field] of [[template.systemPrompt,'systemPrompt'],[template.userTemplate,'userPrompt']]) {
        const expected = source.split(/(\{\{[^{}]+\}\})/g).map(part => part.startsWith('{{') && Object.hasOwn(variables,part.slice(2,-2)) ? variables[part.slice(2,-2)] : part).join('');
        assert.strictEqual(actual[field], expected, `${name}/${field} must preserve input bytes`);
      }
    }
  });
  test('system and user placeholders are one pass with only own variable keys', () => {
    const b = builder();b.templates.set('fixture',{name:'fixture',systemPrompt:'{{code}}|{{filename}}|{{missing}}',userTemplate:'{{code}}|{{evidence}}|{{toString}}',maxTokens:50,temperature:0});
    const value = b.buildPrompt('fixture',{code:literal, filename:'file.js', evidence:'{{code}}'});
    assert.strictEqual(value.systemPrompt,literal+'|file.js|{{missing}}');assert.strictEqual(value.userPrompt,literal+'|{{code}}|{{toString}}');
  });
  for (const command of ['fig.llmAnalyze','fig.llmExplain','fig.llmSuggestRule']) {
    test(`${command} sends literal code/evidence through the consented transport`, async () => {
      const root = fs.mkdtempSync(path.join(os.tmpdir(),'fig-prompt-'));
      const h = createHost(root,{user:{'fig.llm.enabled':true,'fig.llm.provider':'custom','fig.llm.baseUrl':'https://fixture.invalid/v1'}});
      try {
        const file = path.join(root,'literal.js');fs.writeFileSync(file,literal);h.activate();await tick();
        await h.vscode.window.showTextDocument(h.makeDocument(file,literal));h.replies.push('Analyze once');
        const pending = h.commands.get(command)(file,'fixture','description',literal);await tick();assert.strictEqual(h.modelCalls.length,1);
        const sent = h.modelCalls[0].body.messages.find(message=>message.role==='user').content;
        h.modelCalls[0].resolve(modelResponse());await pending;assert(sent.includes(literal),'outgoing code/evidence changed');
      } finally {h.load('extension').deactivate();h.context.subscriptions.forEach(d=>d.dispose());fs.rmSync(root,{recursive:true,force:true});}
    });
  }
});
suite('R3 effective prompt cache identity', () => {
  test('identical bytes with different filename or language do not reuse a verdict', async () => {
    const f = engineFixture();for (const name of ['one.js','two.js','two.py']) assert.strictEqual((await f.engine.analyzeFile(name,'same bytes')).result.fromCache,false,name);
    assert.strictEqual(f.calls.length,3);assert.strictEqual((await f.engine.analyzeFile('two.py','same bytes')).result.fromCache,true);assert.strictEqual(f.calls.length,3);
  });
  test('template text and generation parameter changes invalidate effective context', async () => {
    const f = engineFixture();await f.engine.analyzeFile('one.js','same bytes');
    for (const change of [{userTemplate:'new prompt: {{code}}'}, {systemPrompt:'changed system'}, {maxTokens:12}, {temperature:0.6}]) {
      Object.assign(f.builder.templates.get('Security Analysis'),change);assert.strictEqual((await f.engine.analyzeFile('one.js','same bytes')).result.fromCache,false);
    }assert.strictEqual(f.calls.length,5);
  });
  test('missing profile fallback uses effective prompt and cannot hide removed templates', async () => {
    const f = engineFixture();await f.engine.analyzeFile('one.js','same bytes',{promptOverride:'missing'});
    f.builder.templates.get('Security Analysis').systemPrompt += '\nchanged';assert.strictEqual((await f.engine.analyzeFile('one.js','same bytes',{promptOverride:'missing'})).result.fromCache,false);
    f.builder.templates.clear();await assert.rejects(f.engine.analyzeFile('one.js','same bytes',{promptOverride:'missing'}),/No prompt template/);
  });
  test('cancellation rejects cache hits and late transport results without caching', async () => {
    const f = engineFixture();await f.engine.analyzeFile('one.js','same bytes');const cancelled = new AbortController();cancelled.abort();
    await assert.rejects(f.engine.analyzeFile('one.js','same bytes',{signal:cancelled.signal}),{name:'AbortError'});
    const cache = new LlmCache(), controller = new AbortController();let resolve;
    const engine = new LlmAnalysisEngine({chat:()=>new Promise(r=>{resolve=r;})},cache,builder());
    const pending = engine.analyzeFile('late.js','different',{signal:controller.signal});controller.abort();resolve({content:'{"malicious":false,"threats":[]}',model:'stub'});
    await assert.rejects(pending,{name:'AbortError'});assert.strictEqual(cache.size,0);
  });
});

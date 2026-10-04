import * as vscode from 'vscode';
import * as path from 'path';
import * as fs from 'fs';
import { Scanner } from './scanner/scanner';
import { DiagnosticsProvider } from './providers/diagnostics-provider';
import { CodeActionProvider } from './providers/code-action-provider';
import { ThreatTreeProvider } from './providers/threat-tree-provider';
import { StatusBarProvider } from './providers/status-bar-provider';
import { DashboardPanel } from './providers/dashboard-panel';
import { ScanResult } from './scanner/models/scan-result';
import { Severity } from './scanner/models/severity';
import { LlmClient } from './llm/llm-client';
import { LlmCache } from './llm/llm-cache';
import { PromptBuilder } from './llm/prompt-builder';
import { LlmAnalysisEngine } from './scanner/engines/llm-analysis-engine';
import { readLlmConfig, PROVIDER_DEFAULTS } from './llm/models';
import { TaskInterceptor } from './interceptors/task-interceptor';
import { NpmScriptInterceptor } from './interceptors/npm-script-interceptor';
import { GitConfigInterceptor } from './interceptors/git-config-interceptor';
import { QuarantineManager, QuarantineTreeProvider, QuarantinePanel } from './quarantine';
import { BlockingNotificationService } from './notifications';

let scanner: Scanner;
let diagnosticsProvider: DiagnosticsProvider;
let treeProvider: ThreatTreeProvider;
let statusBar: StatusBarProvider;
let outputChannel: vscode.OutputChannel;

// Security interceptors
let taskInterceptor: TaskInterceptor;
let npmInterceptor: NpmScriptInterceptor;
let gitInterceptor: GitConfigInterceptor;
let quarantineManager: QuarantineManager;
let quarantineTreeProvider: QuarantineTreeProvider;
let notificationService: BlockingNotificationService;

// LLM components (initialized lazily when enabled)
let llmClient: LlmClient | null = null;
let llmCache: LlmCache;
let promptBuilder: PromptBuilder;
let llmEngine: LlmAnalysisEngine | null = null;
const activeAnalyses = new Map<string, AbortController>();
let llmGeneration = 0;
let automaticConsent = '';
function userLlmConfig() {
  return readLlmConfig(key => {
    const setting = vscode.workspace.getConfiguration().inspect(key);
    return setting?.globalValue ?? setting?.defaultValue;
  });
}
function consentKey(): string {
  if (!llmClient) return '';
  const config = llmClient.getConfig();
  return JSON.stringify([config.baseUrl || PROVIDER_DEFAULTS[config.provider]?.baseUrl, config.model,
    vscode.workspace.workspaceFolders?.map(folder => folder.uri.toString()) || []]);
}
async function confirmLlmInput(description: string, allowAutomatic = false, sendsCode = true): Promise<boolean> {
  if (!vscode.workspace.isTrusted || !llmClient) return false;
  const key = consentKey();
  const config = llmClient.getConfig();
  const endpoint = config.baseUrl || PROVIDER_DEFAULTS[config.provider]?.baseUrl || '(not configured)';
  const automatic = allowAutomatic && userLlmConfig().autoAnalyze;
  const choices = automatic ? ['Analyze once', 'Allow automatic analysis this session'] : ['Analyze once'];
  const choice = await vscode.window.showWarningMessage('Send analysis input to the configured model endpoint?', {
    modal: true,
    detail: `${description}\nEndpoint: ${endpoint}\nModel: ${config.model}\n${sendsCode ? 'Code, filename and analysis instructions will be sent. The provider may store input or charge for requests.' : 'Only a model-list request is sent; no code or file contents are included.'} ${automatic ? 'Automatic approval also covers eligible high-severity workspace files for this endpoint, model and workspace in this session.' : ''}`,
  }, ...choices);
  if (key !== consentKey() || !vscode.workspace.isTrusted) return false;
  if (choice === 'Allow automatic analysis this session') { automaticConsent = key; return true; }
  return choice === 'Analyze once';
}
function eligibleAutomaticFile(filePath: string): boolean {
  const folder = vscode.workspace.getWorkspaceFolder(vscode.Uri.file(filePath));
  if (!folder) return false;
  try {
    const stat = fs.lstatSync(filePath);
    if (!stat.isFile() || stat.nlink !== 1) return false;
    const relative = path.relative(fs.realpathSync(folder.uri.fsPath), fs.realpathSync(filePath));
    return relative !== '..' && !relative.startsWith(`..${path.sep}`) && !path.isAbsolute(relative);
  } catch { return false; }
}
function contentStillCurrent(filePath: string, content: string): boolean {
  const doc = vscode.workspace.textDocuments.find(document => document.uri.fsPath === filePath);
  if (doc) return doc.getText() === content;
  try { return fs.readFileSync(filePath, 'utf8') === content; } catch { return false; }
}

export function activate(context: vscode.ExtensionContext) {
  outputChannel = vscode.window.createOutputChannel('FakeInterviewGuard');
  outputChannel.appendLine('FakeInterviewGuard activating...');
  if (!vscode.workspace.isTrusted) {
    outputChannel.appendLine('Disabled in Restricted Mode; no file changes or model requests were made.');
    context.subscriptions.push(outputChannel);
    return;
  }

  // Initialize core components
  scanner = new Scanner();
  diagnosticsProvider = new DiagnosticsProvider();
  treeProvider = new ThreatTreeProvider();
  statusBar = new StatusBarProvider();

  // Initialize configuration inspection and explicit remediation.
  taskInterceptor = new TaskInterceptor(outputChannel);
  npmInterceptor = new NpmScriptInterceptor(outputChannel);
  gitInterceptor = new GitConfigInterceptor(outputChannel);
  quarantineManager = new QuarantineManager(outputChannel);
  quarantineTreeProvider = new QuarantineTreeProvider(quarantineManager);
  notificationService = new BlockingNotificationService(outputChannel);
  notificationService.setQuarantineManager(quarantineManager);
  notificationService.setTaskInterceptor(taskInterceptor);
  notificationService.setNpmInterceptor(npmInterceptor);
  notificationService.setGitInterceptor(gitInterceptor);

  // Set up threat handlers for interceptors
  taskInterceptor.setThreatHandler(result => {
    if (result.hasThreats) {
      notificationService.notifyTaskBlocked(result);
    }
  });

  npmInterceptor.setThreatHandler(result => {
    if (result.hasThreats) {
      notificationService.notifyNpmScriptBlocked(result);
    }
  });

  gitInterceptor.setThreatHandler(result => {
    if (result.hasThreats) {
      notificationService.notifyGitConfigBlocked(result);
    }
  });

  // Inspect workspace on activation; changes require an explicit review action.
  void interceptWorkspaceOnOpen().catch(error => outputChannel.appendLine(`Workspace inspection failed: ${String(error)}`));

  // Load rules
  const rulesDir = path.join(context.extensionPath, 'rules');
  loadRules(rulesDir);

  // Initialize LLM components
  llmCache = new LlmCache();
  promptBuilder = new PromptBuilder();
  const promptsDir = path.join(context.extensionPath, 'prompts');
  promptBuilder.loadTemplatesFromDirectory(promptsDir);
  outputChannel.appendLine(`Loaded prompt templates: ${promptBuilder.getTemplateNames().join(', ') || 'none'}`);
  initializeLlm();

  // Register TreeView
  const treeView = vscode.window.createTreeView('fig.threatExplorer', {
    treeDataProvider: treeProvider,
    showCollapseAll: true,
  });

  // Register Quarantine TreeView
  const quarantineTreeView = vscode.window.createTreeView('fig.quarantine', {
    treeDataProvider: quarantineTreeProvider,
    showCollapseAll: true,
  });

  // Register CodeActionProvider for all relevant languages
  const codeActionProvider = new CodeActionProvider();
  const languages = ['javascript', 'typescript', 'json', 'python', 'shellscript', 'powershell', 'html', 'yaml'];
  for (const lang of languages) {
    context.subscriptions.push(
      vscode.languages.registerCodeActionsProvider(lang, codeActionProvider, {
        providedCodeActionKinds: CodeActionProvider.providedCodeActionKinds,
      })
    );
  }

  // Register commands
  context.subscriptions.push(
    vscode.commands.registerCommand('fig.scanWorkspace', () => scanWorkspace(context)),
    vscode.commands.registerCommand('fig.scanFile', (uri?: vscode.Uri) => scanSingleFile(uri)),
    vscode.commands.registerCommand('fig.showDashboard', () => showDashboard(context)),
    vscode.commands.registerCommand('fig.showQuarantine', () => showQuarantine(context)),
    vscode.commands.registerCommand('fig.quarantineFile', (uri?: vscode.Uri) => quarantineFile(uri)),
    vscode.commands.registerCommand('fig.reloadRules', () => {
      loadRules(rulesDir);
      promptBuilder.loadTemplatesFromDirectory(promptsDir);
      initializeLlm();
      vscode.window.showInformationMessage('FakeInterviewGuard: Rules and config reloaded');
    }),
    vscode.commands.registerCommand('fig.showThreatDetails', (message: string, code: string) => {
      vscode.window.showInformationMessage(`[${code}] ${message}`, 'Open Dashboard').then(selection => {
        if (selection === 'Open Dashboard') {
          showDashboard(context);
        }
      });
    }),
    // LLM commands
    vscode.commands.registerCommand('fig.llmAnalyze', () => llmAnalyzeCurrentFile(context)),
    vscode.commands.registerCommand('fig.llmExplain', (filePath?: string, ruleName?: string, description?: string, evidence?: string) =>
      llmExplainThreat(filePath, ruleName, description, evidence)
    ),
    vscode.commands.registerCommand('fig.llmSuggestRule', () => llmSuggestRule()),
    vscode.commands.registerCommand('fig.llmStatus', () => llmCheckStatus()),
  );

  // Register event handlers
  const config = vscode.workspace.getConfiguration('fig');

  if (config.get<boolean>('scanOnSave', true)) {
    context.subscriptions.push(
      vscode.workspace.onDidSaveTextDocument(doc => {
        scanDocument(doc);
      })
    );
  }

  if (config.get<boolean>('scanOnOpen', true)) {
    context.subscriptions.push(
      vscode.workspace.onDidOpenTextDocument(doc => {
        scanDocument(doc);
      })
    );
  }

  // File watcher for real-time monitoring
  if (config.get<boolean>('realTimeWatching', true)) {
    const watcher = vscode.workspace.createFileSystemWatcher('**/*.{js,mjs,ts,py,json,ps1,sh,yml,yaml,go,mod}');
    const scanExts = ['.js', '.mjs', '.ts', '.py', '.ps1', '.sh', '.json', '.html', '.yml', '.yaml', '.go', '.mod'];

    const scanUri = (uri: vscode.Uri) => {
      if (uri.scheme !== 'file') return;
      const ext = path.extname(uri.fsPath).toLowerCase();
      if (!scanExts.includes(ext)) return;
      try {
        activeAnalyses.get(uri.fsPath)?.abort();
        const result = scanner.scanFile(uri.fsPath, undefined, vscode.workspace.getWorkspaceFolder(uri)?.uri.fsPath);
        diagnosticsProvider.updateFileResults(result);
        updateUI();
      } catch (e: any) {
        outputChannel.appendLine(`File watcher error scanning ${uri.fsPath}: ${e.message}`);
      }
    };

    watcher.onDidCreate(scanUri);
    watcher.onDidChange(scanUri);
    watcher.onDidDelete(uri => { activeAnalyses.get(uri.fsPath)?.abort(); diagnosticsProvider.clearFile(uri.fsPath); updateUI(); });
    context.subscriptions.push(watcher);
  }

  // Listen for config changes
  context.subscriptions.push(
    vscode.workspace.onDidChangeTextDocument(e => { activeAnalyses.get(e.document.uri.fsPath)?.abort(); }),
    vscode.workspace.onDidChangeConfiguration(e => {
      if (e.affectsConfiguration('fig')) { loadRules(rulesDir); updateUI(); }
      if (e.affectsConfiguration('fig.llm')) {
        initializeLlm();
      }
    })
  );

  // Register disposables
  context.subscriptions.push(diagnosticsProvider, statusBar, treeView, quarantineTreeView, outputChannel);

  // Initial scan of open documents
  for (const doc of vscode.workspace.textDocuments) {
    scanDocument(doc);
  }

  const ruleCount = scanner.getRules().length;
  const quarantineCount = quarantineManager.getCount();
  outputChannel.appendLine(`FakeInterviewGuard activated. ${ruleCount} rules loaded, ${quarantineCount} files in quarantine.`);
  vscode.window.showInformationMessage(`FakeInterviewGuard activated — ${ruleCount} detection rules loaded`);
}

async function interceptWorkspaceOnOpen(): Promise<void> {
  const folders = vscode.workspace.workspaceFolders;
  if (!folders) return;

  for (const folder of folders) {
    // Read-only inspection. VS Code controls task execution independently.
    const taskResult = await taskInterceptor.interceptWorkspace(folder);
    if (taskResult?.error) outputChannel.appendLine(`Task inspection incomplete: ${taskResult.error}`);
    if (taskResult?.hasThreats) outputChannel.appendLine(`[STARTUP] Task findings awaiting review in ${folder.name}`);

    // Intercept npm install scripts
    const npmResult = await npmInterceptor.interceptWorkspace(folder);
    if (npmResult?.error) outputChannel.appendLine(`Package inspection incomplete: ${npmResult.error}`);
    if (npmResult?.hasThreats) outputChannel.appendLine(`[STARTUP] Package findings awaiting review in ${folder.name}`);

    // Intercept dangerous git config (core.fsmonitor exploit - March 2026)
    const gitResult = await gitInterceptor.interceptWorkspace(folder);
    if (gitResult?.hasThreats) outputChannel.appendLine(`[STARTUP] Git findings awaiting review in ${folder.name}`);
  }
}

function initializeLlm(): void {
  const config = userLlmConfig();
  llmGeneration++;
  automaticConsent = '';
  for (const controller of activeAnalyses.values()) controller.abort();
  activeAnalyses.clear();
  llmCache?.clear();

  // Clear old references before creating new instances
  llmClient = null;
  llmEngine = null;

  if (config.enabled && vscode.workspace.isTrusted) {
    try {
      llmClient = new LlmClient(config);
      llmEngine = new LlmAnalysisEngine(llmClient, llmCache, promptBuilder, config.promptProfile);
      outputChannel.appendLine(`LLM initialized: ${config.provider} / ${config.model}`);
    } catch (e: any) {
      outputChannel.appendLine(`LLM init failed: ${e.message}`);
      llmClient = null;
      llmEngine = null;
    }
  } else {
    outputChannel.appendLine('LLM disabled');
  }
}

function loadRules(rulesDir: string): void {
  const config = vscode.workspace.getConfiguration('fig');
  const customPath = config.get<string>('customRulesPath', '');
  const rawRuleSets = config.get<string | string[]>('enabledRuleSets', []);
  const enabledRuleSets = Array.isArray(rawRuleSets) ? rawRuleSets : [rawRuleSets];
  const result = scanner.loadRules(rulesDir, customPath || undefined, enabledRuleSets);
  outputChannel.appendLine(`Loaded ${result.count} rules`);
  if (result.errors.length > 0) {
    outputChannel.appendLine(`Rule loading errors:\n${result.errors.join('\n')}`);
  }

  const excluded = config.get<string[]>('excludedPaths', ['**/node_modules/**', '**/.git/**']);
  scanner.setExcludedPatterns(excluded);
  scanner.setMaxFileSizeKB(config.get<number>('maxFileSizeKB', 512));
  diagnosticsProvider.setMinimumSeverity(config.get<string>('minimumSeverity', 'low'));
}

function scanDocument(doc: vscode.TextDocument): void {
  if (doc.uri.scheme !== 'file') return;
  const filePath = doc.uri.fsPath;
  activeAnalyses.get(filePath)?.abort();
  const ext = path.extname(filePath).toLowerCase();
  const scanExts = ['.js', '.mjs', '.ts', '.py', '.ps1', '.sh', '.json', '.html', '.yml', '.yaml', '.go', '.mod'];
  if (!scanExts.includes(ext)) return;

  try {
    const result = scanner.scanFile(filePath, doc.getText(), vscode.workspace.getWorkspaceFolder(doc.uri)?.uri.fsPath);
    diagnosticsProvider.updateFileResults(result);
    updateUI();

    // Auto-analyze with LLM if enabled and threats found
    if (result.status === 'scanned' && llmEngine && result.threats.length > 0) {
      const llmConfig = userLlmConfig();
      if (llmConfig.autoAnalyze) {
        const hasHighSeverity = result.threats.some(t => t.severity <= Severity.HIGH);
        if (hasHighSeverity) {
          runLlmAnalysisBackground(filePath, doc.getText());
        }
      }
    }
  } catch (e: any) {
    outputChannel.appendLine(`Error scanning ${filePath}: ${e.message}`);
  }
}

async function runLlmAnalysisBackground(filePath: string, content: string): Promise<void> {
  const engine = llmEngine;
  if (!engine || !vscode.workspace.isTrusted || automaticConsent !== consentKey() ||
      !eligibleAutomaticFile(filePath)) return;
  const generation = llmGeneration;
  const controller = new AbortController();
  activeAnalyses.get(filePath)?.abort();
  activeAnalyses.set(filePath, controller);
  try {
    const { threats } = await engine.analyzeFile(filePath, content, { signal: controller.signal });
    if (controller.signal.aborted || generation !== llmGeneration || !contentStillCurrent(filePath, content)) return;
    diagnosticsProvider.appendLlmResults(filePath, threats); updateUI();
  } catch (error) {
    if (!controller.signal.aborted) outputChannel.appendLine(`[LLM] Auto-analysis failed: ${String(error)}`);
  } finally {
    if (activeAnalyses.get(filePath) === controller) activeAnalyses.delete(filePath);
  }
}

async function scanSingleFile(uri?: vscode.Uri): Promise<void> {
  const target = uri || vscode.window.activeTextEditor?.document.uri;
  if (!target || target.scheme !== 'file') { vscode.window.showWarningMessage('Select a local file to scan.'); return; }
  try {
    const doc = vscode.workspace.textDocuments.find(d => d.uri.toString() === target.toString()) || await vscode.workspace.openTextDocument(target);
    const result = scanner.scanFile(target.fsPath, doc.getText(), vscode.workspace.getWorkspaceFolder(target)?.uri.fsPath);
    diagnosticsProvider.updateFileResults(result); updateUI();
    if (result.status !== 'scanned') vscode.window.showWarningMessage(`FIG: File not scanned: ${result.detail || result.status}`);
    else vscode.window.showInformationMessage(`FIG: ${result.threats.length} finding(s) in scanned file ${path.basename(target.fsPath)}. A scan is not a safety guarantee.`);
  } catch (error) { vscode.window.showWarningMessage(`FIG: File scan failed: ${String(error)}`); }
}

async function scanWorkspace(_context: vscode.ExtensionContext): Promise<void> {
  const folders = vscode.workspace.workspaceFolders;
  if (!folders) {
    vscode.window.showWarningMessage('No workspace folder open');
    return;
  }

  statusBar.setScanning();
  outputChannel.appendLine('Starting workspace scan...');

  const combined: ScanResult[] = [];
  let scanned = 0, skipped = 0;
  const errors: string[] = [];
  await vscode.window.withProgress(
    { location: vscode.ProgressLocation.Notification, title: 'FakeInterviewGuard: Scanning workspace...', cancellable: false },
    async (progress) => {
      for (const folder of folders) {
        progress.report({ message: folder.name });
        const summary = scanner.scanWorkspace(folder.uri.fsPath);
        combined.push(...summary.results); scanned += summary.scannedFiles; skipped += summary.skippedFiles; errors.push(...summary.errors);
        outputChannel.appendLine(`Scanned ${summary.scannedFiles}/${summary.totalFiles} files in ${summary.durationMs}ms — ${summary.totalThreats} threats found`);
      }
    }
  );

  diagnosticsProvider.updateFromResults(combined);
  updateUI();

  const threats = diagnosticsProvider.getThreats();
  let total = 0;
  for (const t of threats.values()) total += t.length;
  const message = `FIG: ${total} reported finding(s); ${scanned} files scanned, ${skipped} skipped, ${errors.length} error(s). A scan is not a safety guarantee.`;
  if (errors.length) { errors.forEach(error => outputChannel.appendLine(error)); vscode.window.showWarningMessage(message); }
  else vscode.window.showInformationMessage(message);
}

async function llmAnalyzeCurrentFile(context: vscode.ExtensionContext): Promise<void> {
  if (!llmEngine || !llmClient) {
    vscode.window.showWarningMessage('LLM is not enabled. Set fig.llm.enabled = true in settings.');
    return;
  }

  const editor = vscode.window.activeTextEditor;
  if (!editor) {
    vscode.window.showWarningMessage('No file open to analyze');
    return;
  }

  const filePath = editor.document.uri.fsPath;
  const content = editor.document.getText();
  const generation = llmGeneration;
  const engine = llmEngine;
  const skip = scanner.getSkipReason(filePath, vscode.workspace.getWorkspaceFolder(editor.document.uri)?.uri.fsPath, content);
  if (skip) { vscode.window.showWarningMessage(`FIG: Analysis skipped: ${skip}`); return; }
  if (!await confirmLlmInput(`Analyze the selected file: ${filePath}`, true) || generation !== llmGeneration || !contentStillCurrent(filePath, content)) return;
  const controller = new AbortController();
  activeAnalyses.get(filePath)?.abort();
  activeAnalyses.set(filePath, controller);

  await vscode.window.withProgress(
    {
      location: vscode.ProgressLocation.Notification,
      title: `🤖 LLM analyzing: ${path.basename(filePath)}...`,
      cancellable: true,
    },
    async (_progress, token) => {
      let cancelDisposable: vscode.Disposable | undefined;
      try {
        statusBar.setLlmAnalyzing();

        cancelDisposable = token.onCancellationRequested(() => controller.abort());
        if (token.isCancellationRequested) controller.abort();
        const { threats, result } = await engine.analyzeFile(filePath, content, { signal: controller.signal });
        if (controller.signal.aborted || generation !== llmGeneration || !contentStillCurrent(filePath, content)) return;
        diagnosticsProvider.appendLlmResults(filePath, threats); updateUI();

        const status = result.malicious
          ? `🤖 LLM: ${threats.length} threat(s) found (${result.confidence}% confidence)`
          : '🤖 LLM: No findings reported. Model output is advisory.';

        const cached = result.fromCache ? ' [cached]' : ` [${(result.durationMs / 1000).toFixed(1)}s]`;
        outputChannel.appendLine(`[LLM] ${path.basename(filePath)}: ${result.summary}${cached}`);

        vscode.window.showInformationMessage(
          `${status}${cached}`,
          'Show Dashboard', 'View Details'
        ).then(sel => {
          if (sel === 'Show Dashboard') showDashboard(context);
          if (sel === 'View Details') {
            outputChannel.appendLine(`\n--- LLM Analysis: ${path.basename(filePath)} ---`);
            outputChannel.appendLine(`Summary: ${result.summary}`);
            for (const t of result.threats) {
              outputChannel.appendLine(`  [${t.severity.toUpperCase()}] ${t.type}: ${t.evidence}`);
            }
            outputChannel.show();
          }
        });

       } catch (e: any) {
        if (controller.signal.aborted || e.name === 'AbortError') {
          vscode.window.showInformationMessage('LLM analysis cancelled');
        } else {
          outputChannel.appendLine(`[LLM] Error: ${e.message}`);
          vscode.window.showErrorMessage(`LLM analysis failed: ${e.message}`);
        }
      } finally {
        cancelDisposable?.dispose();
        if (activeAnalyses.get(filePath) === controller) activeAnalyses.delete(filePath);
        updateUI();
      }
    }
  );
}

async function llmExplainThreat(
  filePath?: string,
  ruleName?: string,
  description?: string,
  evidence?: string
): Promise<void> {
  if (!llmEngine || !llmClient) {
    vscode.window.showWarningMessage('LLM is not enabled. Set fig.llm.enabled = true in settings.');
    return;
  }

  // If not called with arguments, try to get from active editor diagnostics
  if (!filePath || !ruleName) {
    const editor = vscode.window.activeTextEditor;
    if (!editor) { vscode.window.showWarningMessage('No file open'); return; }
    filePath = editor.document.uri.fsPath;
    const diags = vscode.languages.getDiagnostics(editor.document.uri);
    const figDiag = diags.find(d => d.source === 'FakeInterviewGuard');
    if (!figDiag) { vscode.window.showWarningMessage('No FIG threats in current file'); return; }
    ruleName = String(figDiag.code || 'unknown');
    description = figDiag.message;
    evidence = editor.document.getText(figDiag.range);
  }

  const engine = llmEngine;
  const generation = llmGeneration;
  if (!await confirmLlmInput(`Explain finding in ${filePath}: the finding description and selected evidence will be sent.`) || generation !== llmGeneration) return;
  const controller = new AbortController();
  activeAnalyses.get(filePath)?.abort();
  activeAnalyses.set(filePath, controller);
  await vscode.window.withProgress(
    { location: vscode.ProgressLocation.Notification, title: '🤖 Generating explanation...', cancellable: true },
    async (_progress, token) => {
      const cancelDisposable = token.onCancellationRequested(() => controller.abort());
      try {
        if (token.isCancellationRequested) controller.abort();
        const explanation = await engine.explainThreat(filePath!, ruleName!, description || '', evidence || '', { signal: controller.signal });
        if (controller.signal.aborted || generation !== llmGeneration) return;
        outputChannel.appendLine(`\n--- LLM Threat Explanation ---\n${explanation}`);
        outputChannel.show();
        vscode.window.showInformationMessage('Explanation written to Output channel');
      } catch (e: any) {
        if (!controller.signal.aborted) vscode.window.showErrorMessage(`LLM explain failed: ${e.message}`);
      } finally {
        cancelDisposable.dispose();
        if (activeAnalyses.get(filePath!) === controller) activeAnalyses.delete(filePath!);
      }
    }
  );
}

async function llmSuggestRule(): Promise<void> {
  if (!llmEngine || !llmClient) {
    vscode.window.showWarningMessage('LLM is not enabled. Set fig.llm.enabled = true in settings.');
    return;
  }

  const editor = vscode.window.activeTextEditor;
  if (!editor) { vscode.window.showWarningMessage('No file open'); return; }

  const content = editor.document.getText(editor.selection.isEmpty ? undefined : editor.selection);
  const documentContent = editor.document.getText();
  const filePath = editor.document.uri.fsPath;

  const engine = llmEngine;
  const generation = llmGeneration;
  if (!await confirmLlmInput(`Suggest a rule using selected code from ${filePath}.`) || generation !== llmGeneration || !contentStillCurrent(filePath, documentContent)) return;
  const controller = new AbortController();
  activeAnalyses.get(filePath)?.abort();
  activeAnalyses.set(filePath, controller);
  await vscode.window.withProgress(
    { location: vscode.ProgressLocation.Notification, title: '🤖 Generating detection rule...', cancellable: true },
    async (_progress, token) => {
      const cancelDisposable = token.onCancellationRequested(() => controller.abort());
      try {
        if (token.isCancellationRequested) controller.abort();
        const ruleJson = await engine.suggestRule(filePath, content, { signal: controller.signal });
        if (controller.signal.aborted || generation !== llmGeneration || !contentStillCurrent(filePath, documentContent)) return;
        const doc = await vscode.workspace.openTextDocument({ content: ruleJson, language: 'json' });
        await vscode.window.showTextDocument(doc);
        vscode.window.showInformationMessage('LLM-suggested rule opened. Save to extension/rules/ to activate.');
      } catch (e: any) {
        if (!controller.signal.aborted) vscode.window.showErrorMessage(`LLM rule suggestion failed: ${e.message}`);
      } finally {
        cancelDisposable.dispose();
        if (activeAnalyses.get(filePath) === controller) activeAnalyses.delete(filePath);
      }
    }
  );
}

async function llmCheckStatus(): Promise<void> {
  if (!llmClient) { vscode.window.showInformationMessage('LLM is disabled. Configure it in User settings.'); return; }
  if (!await confirmLlmInput('Check provider health by requesting its model list.', false, false)) return;
  const client = llmClient;
  if (!client) return;
  const result = await client.checkHealth();
  if (result.ok) vscode.window.showInformationMessage(`LLM provider reachable. Models: ${result.models.join(', ')}`);
  else vscode.window.showWarningMessage(`LLM provider check failed: ${result.error}`);
}

function showDashboard(context: vscode.ExtensionContext): void {
  const panel = DashboardPanel.createOrShow(context.extensionUri);
  panel.update(diagnosticsProvider.getThreats());
}

function showQuarantine(context: vscode.ExtensionContext): void {
  QuarantinePanel.createOrShow(context.extensionUri, quarantineManager);
}

async function quarantineFile(uri?: vscode.Uri): Promise<void> {
  const targetUri = uri || vscode.window.activeTextEditor?.document.uri;
  if (!targetUri || targetUri.scheme !== 'file') {
    vscode.window.showWarningMessage('No file selected to quarantine');
    return;
  }

  const filePath = targetUri.fsPath;
  if (!vscode.workspace.isTrusted || vscode.workspace.textDocuments.some(d => d.uri.fsPath === filePath && d.isDirty)) {
    vscode.window.showWarningMessage('FIG: Quarantine requires a trusted workspace and no unsaved edits in the selected file.');
    return;
  }
  let reviewedContent: Buffer;
  try { reviewedContent = fs.readFileSync(filePath); } catch { vscode.window.showWarningMessage('FIG: Selected file cannot be read.'); return; }
  const confirmed = await vscode.window.showWarningMessage('Move this file to quarantine?', {
    modal: true, detail: `${filePath}\nThis removes the original after saving a recovery copy and can disrupt the project.`,
  }, 'Quarantine file');
  if (confirmed !== 'Quarantine file' || !vscode.workspace.isTrusted ||
      vscode.workspace.textDocuments.some(d => d.uri.fsPath === filePath && d.isDirty)) return;
  try {
    if (!fs.readFileSync(filePath).equals(reviewedContent)) { vscode.window.showWarningMessage('FIG: File changed during confirmation. Inspect it again before quarantining.'); return; }
  } catch { return; }
  const threats = diagnosticsProvider.getThreats().get(filePath) || [];

  const result = await quarantineManager.quarantine(filePath, threats);
  if (result) {
    vscode.window.showInformationMessage(`File quarantined: ${result.fileName}`);
    diagnosticsProvider.clearFile(filePath);
    updateUI();
  } else {
    vscode.window.showErrorMessage(`Quarantine did not complete: ${quarantineManager.getLastError() || 'Inspect the source and recovery copies before retrying.'}`);
  }
}

function updateUI(): void {
  const threats = diagnosticsProvider.getThreats();
  treeProvider.refresh(threats);

  let total = 0;
  let maxSeverity = Severity.INFO;
  for (const threatList of threats.values()) {
    total += threatList.length;
    for (const t of threatList) {
      if (t.severity < maxSeverity) maxSeverity = t.severity;
    }
  }

  if (total > 0) {
    statusBar.setThreats(total, maxSeverity);
  } else {
    statusBar.setClean();
  }

  if (DashboardPanel.currentPanel) {
    DashboardPanel.currentPanel.update(threats);
  }
}

export function deactivate() {
  outputChannel?.appendLine('FakeInterviewGuard deactivating...');
  llmClient = null;
  llmEngine = null;
  for (const controller of activeAnalyses.values()) controller.abort();
  activeAnalyses.clear();
  automaticConsent = '';
  llmGeneration++;
  llmCache?.clear();
}

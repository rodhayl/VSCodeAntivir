import * as vscode from 'vscode';
import * as path from 'path';
import { Scanner } from './scanner/scanner';
import { DiagnosticsProvider } from './providers/diagnostics-provider';
import { CodeActionProvider } from './providers/code-action-provider';
import { ThreatTreeProvider } from './providers/threat-tree-provider';
import { StatusBarProvider } from './providers/status-bar-provider';
import { DashboardPanel } from './providers/dashboard-panel';
import { Severity } from './scanner/models/severity';
import { LlmClient } from './llm/llm-client';
import { LlmCache } from './llm/llm-cache';
import { PromptBuilder } from './llm/prompt-builder';
import { LlmAnalysisEngine } from './scanner/engines/llm-analysis-engine';
import { readLlmConfig } from './llm/models';
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

export function activate(context: vscode.ExtensionContext) {
  outputChannel = vscode.window.createOutputChannel('FakeInterviewGuard');
  outputChannel.appendLine('FakeInterviewGuard activating...');

  // Initialize core components
  scanner = new Scanner();
  diagnosticsProvider = new DiagnosticsProvider();
  treeProvider = new ThreatTreeProvider();
  statusBar = new StatusBarProvider();

  // Initialize security interceptors (CRITICAL - must run early)
  taskInterceptor = new TaskInterceptor(outputChannel);
  npmInterceptor = new NpmScriptInterceptor(outputChannel);
  gitInterceptor = new GitConfigInterceptor(outputChannel);
  quarantineManager = new QuarantineManager(outputChannel);
  quarantineTreeProvider = new QuarantineTreeProvider(quarantineManager);
  notificationService = new BlockingNotificationService(outputChannel);
  notificationService.setQuarantineManager(quarantineManager);

  // Set up threat handlers for interceptors
  taskInterceptor.setThreatHandler(result => {
    if (result.blocked) {
      notificationService.notifyTaskBlocked(result);
    }
  });

  npmInterceptor.setThreatHandler(result => {
    if (result.blocked) {
      notificationService.notifyNpmScriptBlocked(result);
    }
  });

  gitInterceptor.setThreatHandler(result => {
    if (result.blocked) {
      notificationService.notifyGitConfigBlocked(result);
    }
  });

  // Intercept workspace on activation (BEFORE VS Code processes tasks)
  interceptWorkspaceOnOpen();

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
    const watcher = vscode.workspace.createFileSystemWatcher('**/*.{js,mjs,ts,py,json,ps1,sh}');
    watcher.onDidCreate(uri => {
      const doc = vscode.workspace.textDocuments.find(d => d.uri.toString() === uri.toString());
      if (doc) scanDocument(doc);
    });
    watcher.onDidChange(uri => {
      const doc = vscode.workspace.textDocuments.find(d => d.uri.toString() === uri.toString());
      if (doc) scanDocument(doc);
    });
    context.subscriptions.push(watcher);
  }

  // Listen for config changes
  context.subscriptions.push(
    vscode.workspace.onDidChangeConfiguration(e => {
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
    // Intercept tasks.json BEFORE VS Code processes it
    const taskResult = await taskInterceptor.interceptWorkspace(folder);
    if (taskResult?.blocked) {
      outputChannel.appendLine(`[STARTUP] Blocked malicious tasks.json in ${folder.name}`);
    }

    // Intercept npm install scripts
    const npmResult = await npmInterceptor.interceptWorkspace(folder);
    if (npmResult?.blocked) {
      outputChannel.appendLine(`[STARTUP] Blocked malicious npm scripts in ${folder.name}`);
    }

    // Intercept dangerous git config (core.fsmonitor exploit - March 2026)
    const gitResult = await gitInterceptor.interceptWorkspace(folder);
    if (gitResult?.blocked) {
      outputChannel.appendLine(`[STARTUP] Blocked dangerous git config in ${folder.name}`);
    }
  }
}

function initializeLlm(): void {
  const config = readLlmConfig((key: string) => {
    return vscode.workspace.getConfiguration().get(key);
  });

  if (config.enabled) {
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
    llmClient = null;
    llmEngine = null;
    outputChannel.appendLine('LLM disabled');
  }
}

function loadRules(rulesDir: string): void {
  const config = vscode.workspace.getConfiguration('fig');
  const customPath = config.get<string>('customRulesPath', '');
  const enabledRuleSets = config.get<string[]>('enabledRuleSets', []);
  const result = scanner.loadRules(rulesDir, customPath || undefined, enabledRuleSets);
  outputChannel.appendLine(`Loaded ${result.count} rules`);
  if (result.errors.length > 0) {
    outputChannel.appendLine(`Rule loading errors:\n${result.errors.join('\n')}`);
  }

  const excluded = config.get<string[]>('excludedPaths', ['**/node_modules/**', '**/.git/**']);
  scanner.setExcludedPatterns(excluded);
  scanner.setMaxFileSizeKB(config.get<number>('maxFileSizeKB', 512));
}

function scanDocument(doc: vscode.TextDocument): void {
  if (doc.uri.scheme !== 'file') return;
  const filePath = doc.uri.fsPath;
  const ext = path.extname(filePath).toLowerCase();
  const scanExts = ['.js', '.mjs', '.ts', '.py', '.ps1', '.sh', '.json', '.html', '.yml', '.yaml', '.go', '.mod'];
  if (!scanExts.includes(ext)) return;

  try {
    const result = scanner.scanFile(filePath, doc.getText());
    diagnosticsProvider.updateFileResults(result);
    updateUI();

    // Auto-analyze with LLM if enabled and threats found
    if (llmEngine && result.threats.length > 0) {
      const llmConfig = readLlmConfig((key: string) => vscode.workspace.getConfiguration().get(key));
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
  if (!llmEngine) return;
  try {
    outputChannel.appendLine(`[LLM] Auto-analyzing: ${path.basename(filePath)}`);
    const { threats, result } = await llmEngine.analyzeFile(filePath, content);
    if (threats.length > 0) {
      diagnosticsProvider.appendLlmResults(filePath, threats);
      updateUI();
      outputChannel.appendLine(`[LLM] Found ${threats.length} threat(s) in ${path.basename(filePath)} [${result.durationMs}ms, ${result.fromCache ? 'cached' : 'live'}]`);
    }
  } catch (e: any) {
    outputChannel.appendLine(`[LLM] Auto-analysis error: ${e.message}`);
  }
}

function scanSingleFile(uri?: vscode.Uri): void {
  const targetUri = uri || vscode.window.activeTextEditor?.document.uri;
  if (!targetUri) {
    vscode.window.showWarningMessage('No file selected to scan');
    return;
  }

  const doc = vscode.workspace.textDocuments.find(d => d.uri.toString() === targetUri.toString());
  if (doc) {
    scanDocument(doc);
    const threats = diagnosticsProvider.getThreats().get(targetUri.fsPath) || [];
    vscode.window.showInformationMessage(
      threats.length > 0
        ? `FIG: Found ${threats.length} threat(s) in ${path.basename(targetUri.fsPath)}`
        : `FIG: No threats in ${path.basename(targetUri.fsPath)}`
    );
  }
}

async function scanWorkspace(_context: vscode.ExtensionContext): Promise<void> {
  const folders = vscode.workspace.workspaceFolders;
  if (!folders) {
    vscode.window.showWarningMessage('No workspace folder open');
    return;
  }

  statusBar.setScanning();
  outputChannel.appendLine('Starting workspace scan...');

  await vscode.window.withProgress(
    { location: vscode.ProgressLocation.Notification, title: 'FakeInterviewGuard: Scanning workspace...', cancellable: false },
    async (progress) => {
      for (const folder of folders) {
        progress.report({ message: folder.name });
        const summary = scanner.scanWorkspace(folder.uri.fsPath);
        diagnosticsProvider.updateFromResults(summary.results);
        outputChannel.appendLine(`Scanned ${summary.scannedFiles}/${summary.totalFiles} files in ${summary.durationMs}ms — ${summary.totalThreats} threats found`);
      }
    }
  );

  updateUI();

  const threats = diagnosticsProvider.getThreats();
  let total = 0;
  for (const t of threats.values()) total += t.length;
  vscode.window.showInformationMessage(
    total > 0
      ? `FakeInterviewGuard: ${total} threat(s) detected across workspace`
      : 'FakeInterviewGuard: Workspace is clean ✅'
  );
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

  await vscode.window.withProgress(
    {
      location: vscode.ProgressLocation.Notification,
      title: `🤖 LLM analyzing: ${path.basename(filePath)}...`,
      cancellable: true,
    },
    async (_progress, token) => {
      try {
        statusBar.setLlmAnalyzing();

        const analysisPromise = llmEngine!.analyzeFile(filePath, content);
        const cancelPromise = new Promise<never>((_, reject) => {
          token.onCancellationRequested(() => reject(new Error('Cancelled')));
        });

        const { threats, result } = await Promise.race([analysisPromise, cancelPromise]);

        if (threats.length > 0) {
          diagnosticsProvider.appendLlmResults(filePath, threats);
          updateUI();
        }

        const status = result.malicious
          ? `🤖 LLM: ${threats.length} threat(s) found (${result.confidence}% confidence)`
          : `🤖 LLM: Code appears clean (${result.confidence}% confidence)`;

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
        if (e.message === 'Cancelled') {
          vscode.window.showInformationMessage('LLM analysis cancelled');
        } else {
          outputChannel.appendLine(`[LLM] Error: ${e.message}`);
          vscode.window.showErrorMessage(`LLM analysis failed: ${e.message}`);
        }
      } finally {
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

  await vscode.window.withProgress(
    { location: vscode.ProgressLocation.Notification, title: '🤖 Generating explanation...' },
    async () => {
      try {
        const explanation = await llmEngine!.explainThreat(filePath!, ruleName!, description || '', evidence || '');
        outputChannel.appendLine(`\n--- LLM Threat Explanation ---\n${explanation}`);
        outputChannel.show();
        vscode.window.showInformationMessage('Explanation written to Output channel');
      } catch (e: any) {
        vscode.window.showErrorMessage(`LLM explain failed: ${e.message}`);
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
  const filePath = editor.document.uri.fsPath;

  await vscode.window.withProgress(
    { location: vscode.ProgressLocation.Notification, title: '🤖 Generating detection rule...' },
    async () => {
      try {
        const ruleJson = await llmEngine!.suggestRule(filePath, content);
        const doc = await vscode.workspace.openTextDocument({ content: ruleJson, language: 'json' });
        await vscode.window.showTextDocument(doc);
        vscode.window.showInformationMessage('LLM-suggested rule opened. Save to extension/rules/ to activate.');
      } catch (e: any) {
        vscode.window.showErrorMessage(`LLM rule suggestion failed: ${e.message}`);
      }
    }
  );
}

async function llmCheckStatus(): Promise<void> {
  if (!llmClient) {
    const config = readLlmConfig((key: string) => vscode.workspace.getConfiguration().get(key));
    if (!config.enabled) {
      vscode.window.showInformationMessage('LLM is disabled. Set fig.llm.enabled = true to enable.');
      return;
    }
    // Try to create a temporary client for checking
    const tmpClient = new LlmClient(config);
    const result = await tmpClient.checkHealth();
    if (result.ok) {
      vscode.window.showInformationMessage(`✅ LLM provider reachable. Models: ${result.models.join(', ')}`);
    } else {
      vscode.window.showErrorMessage(`❌ LLM provider not reachable: ${result.error}`);
    }
    return;
  }

  const result = await llmClient.checkHealth();
  const config = llmClient.getConfig();
  if (result.ok) {
    vscode.window.showInformationMessage(
      `✅ LLM connected: ${config.provider} / ${config.model}\nModels: ${result.models.join(', ')}`
    );
  } else {
    vscode.window.showErrorMessage(`❌ LLM connection failed: ${result.error}`);
  }
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
  const threats = diagnosticsProvider.getThreats().get(filePath) || [];

  const result = await quarantineManager.quarantine(filePath, threats);
  if (result) {
    vscode.window.showInformationMessage(`File quarantined: ${result.fileName}`);
    diagnosticsProvider.clearFile(filePath);
    updateUI();
  } else {
    vscode.window.showErrorMessage('Failed to quarantine file');
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
}

import * as vscode from 'vscode';
import { Threat } from '../scanner/models/threat';
import { Severity } from '../scanner/models/severity';
import { ScanResult } from '../scanner/models/scan-result';

export class DiagnosticsProvider {
  private collection: vscode.DiagnosticCollection;
  private threatMap: Map<string, Threat[]> = new Map();

  constructor() {
    this.collection = vscode.languages.createDiagnosticCollection('fakeInterviewGuard');
  }

  updateFromResults(results: ScanResult[]): void {
    this.collection.clear();
    this.threatMap.clear();

    for (const result of results) {
      if (result.threats.length === 0) continue;
      const uri = vscode.Uri.file(result.filePath);
      const diagnostics: vscode.Diagnostic[] = [];

      for (const threat of result.threats) {
        const range = new vscode.Range(
          new vscode.Position(threat.location.startLine, threat.location.startCol),
          new vscode.Position(threat.location.endLine, Math.max(threat.location.endCol, threat.location.startCol + 1))
        );

        const severity = this.mapSeverity(threat.severity);
        const diagnostic = new vscode.Diagnostic(range, threat.message, severity);
        diagnostic.source = 'FakeInterviewGuard';
        diagnostic.code = threat.ruleId;

        if (threat.matchedStrings.length > 0) {
          diagnostic.relatedInformation = threat.matchedStrings.slice(0, 3).map(ms =>
            new vscode.DiagnosticRelatedInformation(
              new vscode.Location(uri, range),
              `Matched: ${ms}`
            )
          );
        }

        diagnostics.push(diagnostic);
      }

      this.collection.set(uri, diagnostics);
      this.threatMap.set(result.filePath, result.threats);
    }
  }

  updateFileResults(result: ScanResult): void {
    const uri = vscode.Uri.file(result.filePath);
    if (result.threats.length === 0) {
      this.collection.delete(uri);
      this.threatMap.delete(result.filePath);
      return;
    }

    const diagnostics: vscode.Diagnostic[] = result.threats.map(threat => {
      const range = new vscode.Range(
        new vscode.Position(threat.location.startLine, threat.location.startCol),
        new vscode.Position(threat.location.endLine, Math.max(threat.location.endCol, threat.location.startCol + 1))
      );
      const d = new vscode.Diagnostic(range, threat.message, this.mapSeverity(threat.severity));
      d.source = 'FakeInterviewGuard';
      d.code = threat.ruleId;
      return d;
    });

    this.collection.set(uri, diagnostics);
    this.threatMap.set(result.filePath, result.threats);
  }

  appendLlmResults(filePath: string, llmThreats: Threat[]): void {
    const existing = this.threatMap.get(filePath) || [];
    // Remove old LLM findings, keep rule-based ones
    const filtered = existing.filter(t => !t.ruleId.startsWith('llm-'));
    const merged = [...filtered, ...llmThreats];
    this.threatMap.set(filePath, merged);

    // Update diagnostics
    const uri = vscode.Uri.file(filePath);
    const diagnostics: vscode.Diagnostic[] = merged.map(threat => {
      const range = new vscode.Range(
        new vscode.Position(threat.location.startLine, threat.location.startCol),
        new vscode.Position(threat.location.endLine, Math.max(threat.location.endCol, threat.location.startCol + 1))
      );
      const d = new vscode.Diagnostic(range, threat.message, this.mapSeverity(threat.severity));
      d.source = 'FakeInterviewGuard';
      d.code = threat.ruleId;
      return d;
    });
    this.collection.set(uri, diagnostics);
  }

  getThreats(): Map<string, Threat[]> {
    return new Map(this.threatMap);
  }

  clear(): void {
    this.collection.clear();
    this.threatMap.clear();
  }

  clearFile(filePath: string): void {
    const uri = vscode.Uri.file(filePath);
    this.collection.delete(uri);
    this.threatMap.delete(filePath);
  }

  dispose(): void {
    this.collection.dispose();
  }

  private mapSeverity(severity: Severity): vscode.DiagnosticSeverity {
    switch (severity) {
      case Severity.CRITICAL:
      case Severity.HIGH:
        return vscode.DiagnosticSeverity.Error;
      case Severity.MEDIUM:
        return vscode.DiagnosticSeverity.Warning;
      case Severity.LOW:
        return vscode.DiagnosticSeverity.Information;
      case Severity.INFO:
        return vscode.DiagnosticSeverity.Hint;
    }
  }
}

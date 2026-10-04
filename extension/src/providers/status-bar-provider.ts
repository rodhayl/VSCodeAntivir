import * as vscode from 'vscode';
import { Severity } from '../scanner/models/severity';

export class StatusBarProvider {
  private item: vscode.StatusBarItem;

  constructor() {
    this.item = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left, 100);
    this.item.command = 'fig.scanWorkspace';
    this.setClean();
    this.item.show();
  }

  setClean(): void {
    this.item.text = '$(shield) FIG: No findings';
    this.item.backgroundColor = undefined;
    this.item.tooltip = 'FakeInterviewGuard — No reported findings. Unscanned files may remain; a scan is not a safety guarantee. Click to scan.';
  }

  setScanning(): void {
    this.item.text = '$(sync~spin) FIG: Scanning...';
    this.item.tooltip = 'FakeInterviewGuard — Scanning workspace...';
  }

  setLlmAnalyzing(): void {
    this.item.text = '$(hubot~spin) FIG: LLM analyzing...';
    this.item.tooltip = 'FakeInterviewGuard — LLM deep analysis in progress...';
  }

  setThreats(count: number, maxSeverity: Severity): void {
    this.item.text = `$(warning) FIG: ${count} threat${count !== 1 ? 's' : ''}`;
    if (maxSeverity <= Severity.HIGH) {
      this.item.backgroundColor = new vscode.ThemeColor('statusBarItem.errorBackground');
    } else {
      this.item.backgroundColor = new vscode.ThemeColor('statusBarItem.warningBackground');
    }
    this.item.tooltip = `FakeInterviewGuard — ${count} threat(s) detected. Click to scan.`;
  }

  dispose(): void {
    this.item.dispose();
  }
}

import * as vscode from 'vscode';
import { Threat } from '../scanner/models/threat';
import { Severity, severityToString } from '../scanner/models/severity';

interface ThreatGroup {
  tactic: string;
  threats: Threat[];
}

class ThreatTreeItem extends vscode.TreeItem {
  constructor(
    public readonly label: string,
    public readonly collapsibleState: vscode.TreeItemCollapsibleState,
    public readonly threat?: Threat,
    public readonly isGroup?: boolean,
    public readonly childCount?: number,
  ) {
    super(label, collapsibleState);

    if (threat) {
      this.tooltip = `${threat.ruleName}\n${threat.message}\nFile: ${threat.filePath}`;
      this.description = `[${severityToString(threat.severity).toUpperCase()}]`;
      this.iconPath = this.getSeverityIcon(threat.severity);
      this.command = {
        command: 'vscode.open',
        title: 'Open File',
        arguments: [
          vscode.Uri.file(threat.filePath),
          { selection: new vscode.Range(threat.location.startLine, threat.location.startCol, threat.location.endLine, threat.location.endCol) },
        ],
      };
    } else if (isGroup) {
      this.description = `(${childCount || 0})`;
    }
  }

  private getSeverityIcon(severity: Severity): vscode.ThemeIcon {
    switch (severity) {
      case Severity.CRITICAL: return new vscode.ThemeIcon('error', new vscode.ThemeColor('errorForeground'));
      case Severity.HIGH: return new vscode.ThemeIcon('warning', new vscode.ThemeColor('editorWarning.foreground'));
      case Severity.MEDIUM: return new vscode.ThemeIcon('warning');
      case Severity.LOW: return new vscode.ThemeIcon('info');
      case Severity.INFO: return new vscode.ThemeIcon('comment');
    }
  }
}

export class ThreatTreeProvider implements vscode.TreeDataProvider<ThreatTreeItem> {
  private _onDidChangeTreeData = new vscode.EventEmitter<ThreatTreeItem | undefined | null>();
  readonly onDidChangeTreeData = this._onDidChangeTreeData.event;

  private groups: ThreatGroup[] = [];

  refresh(threatMap: Map<string, Threat[]>): void {
    const allThreats: Threat[] = [];
    for (const threats of threatMap.values()) {
      allThreats.push(...threats);
    }

    // Group by MITRE tactic
    const groupMap = new Map<string, Threat[]>();
    for (const threat of allThreats) {
      const tactic = threat.mitre?.tactic || 'Other';
      if (!groupMap.has(tactic)) groupMap.set(tactic, []);
      groupMap.get(tactic)!.push(threat);
    }

    this.groups = Array.from(groupMap.entries())
      .map(([tactic, threats]) => ({ tactic, threats }))
      .sort((a, b) => {
        // Sort by highest severity threat in each group
        const minA = Math.min(...a.threats.map(t => t.severity));
        const minB = Math.min(...b.threats.map(t => t.severity));
        return minA - minB;
      });

    this._onDidChangeTreeData.fire(null);
  }

  getTreeItem(element: ThreatTreeItem): ThreatTreeItem {
    return element;
  }

  getChildren(element?: ThreatTreeItem): ThreatTreeItem[] {
    if (!element) {
      // Root: show groups
      if (this.groups.length === 0) {
        return [new ThreatTreeItem('✅ No threats detected', vscode.TreeItemCollapsibleState.None)];
      }
      return this.groups.map(g =>
        new ThreatTreeItem(
          this.getTacticIcon(g.tactic) + ' ' + g.tactic,
          vscode.TreeItemCollapsibleState.Expanded,
          undefined,
          true,
          g.threats.length,
        )
      );
    }

    // Children: show threats in this tactic group
    if (element.isGroup) {
      const tacticName = element.label?.replace(/^[^\s]+\s/, '') || '';
      const group = this.groups.find(g => g.tactic === tacticName);
      if (!group) return [];
      return group.threats.map(t => {
        const fileName = t.filePath.split(/[/\\]/).pop() || t.filePath;
        return new ThreatTreeItem(
          `${t.ruleName}: ${fileName}`,
          vscode.TreeItemCollapsibleState.None,
          t,
        );
      });
    }

    return [];
  }

  private getTacticIcon(tactic: string): string {
    const icons: Record<string, string> = {
      'Initial Access': '🔓',
      'Execution': '⚡',
      'Persistence': '📌',
      'Defense Evasion': '🛡️',
      'Credential Access': '🔑',
      'Discovery': '🔍',
      'Collection': '📦',
      'Exfiltration': '📤',
      'Command and Control': '📡',
      'Other': '❓',
    };
    return icons[tactic] || '❓';
  }
}

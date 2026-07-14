import { LlmAnalysisResult, LlmFinding } from './models';
import { Threat, ThreatLocation } from '../scanner/models/threat';
import { stringToSeverity } from '../scanner/models/severity';

export class ResponseParser {

  parseAnalysisResponse(raw: string, model: string, durationMs: number): LlmAnalysisResult {
    const json = this.extractJson(raw);
    if (!json) {
      return this.fallbackResult(raw, model, durationMs);
    }

    return {
      malicious: !!json.malicious,
      confidence: typeof json.confidence === 'number' ? json.confidence : 50,
      threats: Array.isArray(json.threats) ? (json.threats as any[]).map((t) => ({
        type: t.type || 'Unknown Threat',
        severity: t.severity || 'medium',
        evidence: t.evidence || '',
        line: typeof t.line === 'number' ? t.line : null,
        recommendation: t.recommendation || '',
      })) : [],
      summary: json.summary || '',
      campaignMatch: json.campaign_match,
      malwareFamily: json.malware_family,
      rawResponse: raw,
      model,
      durationMs,
      fromCache: false,
    };
  }

  private extractJson(text: string): any | null {
    // Try 1: Direct parse
    try { return JSON.parse(text.trim()); } catch {}

    // Try 2: Markdown code fence
    const fenceMatch = text.match(/```(?:json)?\s*\r?\n?([\s\S]*?)\r?\n?```/);
    if (fenceMatch) {
      try { return JSON.parse(fenceMatch[1].trim()); } catch {}
    }

    // Try 3: First { ... } block
    const braceStart = text.indexOf('{');
    const braceEnd = text.lastIndexOf('}');
    if (braceStart !== -1 && braceEnd > braceStart) {
      try { return JSON.parse(text.substring(braceStart, braceEnd + 1)); } catch {}
    }

    return null;
  }

  private fallbackResult(raw: string, model: string, durationMs: number): LlmAnalysisResult {
    return {
      malicious: false,
      confidence: 0,
      threats: [],
      summary: `LLM response could not be parsed. Raw: ${raw.substring(0, 200)}`,
      rawResponse: raw,
      model,
      durationMs,
      fromCache: false,
    };
  }

  mapToThreats(result: LlmAnalysisResult, filePath: string, content: string): Threat[] {
    if (!result.malicious || result.threats.length === 0) return [];

    return result.threats.map((finding, idx) => {
      const line = (finding.line && finding.line > 0) ? finding.line - 1 : 0;
      const location: ThreatLocation = { startLine: line, startCol: 0, endLine: line, endCol: 200 };

      // Try to find the evidence string in the content for a better location
      if (finding.evidence) {
        const evidenceClean = finding.evidence.substring(0, 80);
        const evidenceIdx = content.indexOf(evidenceClean);
        if (evidenceIdx >= 0) {
          const before = content.substring(0, evidenceIdx);
          const lineNum = before.split('\n').length - 1;
          const lastNewline = before.lastIndexOf('\n');
          const col = evidenceIdx - lastNewline - 1;
          location.startLine = lineNum;
          location.startCol = Math.max(0, col);
          location.endLine = lineNum;
          location.endCol = Math.min(col + evidenceClean.length, 500);
        }
      }

      const ruleId = `llm-${finding.type.toLowerCase().replace(/[^a-z0-9]+/g, '-').substring(0, 30)}`;
      return {
        id: `${ruleId}-${idx}`,
        ruleId,
        ruleName: `🤖 ${finding.type}`,
        severity: stringToSeverity(finding.severity),
        confidence: `llm-${result.confidence}%`,
        message: `[LLM] ${finding.evidence}${finding.recommendation ? ' — ' + finding.recommendation : ''}`,
        filePath,
        location,
        matchedStrings: finding.evidence ? [finding.evidence.substring(0, 120)] : [],
        remediation: finding.recommendation ? { message: finding.recommendation, actions: ['review'] } : undefined,
      };
    });
  }
}

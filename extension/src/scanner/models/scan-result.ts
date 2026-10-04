import { Threat } from './threat';

export interface ScanResult {
  filePath: string;
  threats: Threat[];
  scanDurationMs: number;
  status?: 'scanned' | 'skipped' | 'error';
  detail?: string;
}

export interface ScanSummary {
  totalFiles: number;
  scannedFiles: number;
  skippedFiles: number;
  failedFiles: number;
  errors: string[];
  threatsBySeverity: Record<string, number>;
  totalThreats: number;
  durationMs: number;
  results: ScanResult[];
}

export function createEmptySummary(): ScanSummary {
  return {
    totalFiles: 0,
    scannedFiles: 0,
    skippedFiles: 0,
    failedFiles: 0,
    errors: [],
    threatsBySeverity: {
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      info: 0,
    },
    totalThreats: 0,
    durationMs: 0,
    results: [],
  };
}

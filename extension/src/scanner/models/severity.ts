export enum Severity {
  CRITICAL = 0,
  HIGH = 1,
  MEDIUM = 2,
  LOW = 3,
  INFO = 4,
}

export function severityToString(s: Severity): string {
  return ['critical', 'high', 'medium', 'low', 'info'][s];
}

export function stringToSeverity(s: string): Severity {
  const map: Record<string, Severity> = {
    critical: Severity.CRITICAL,
    high: Severity.HIGH,
    medium: Severity.MEDIUM,
    low: Severity.LOW,
    info: Severity.INFO,
  };
  return map[s.toLowerCase()] ?? Severity.INFO;
}

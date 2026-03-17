import { ThreatAnalysisResult } from './threat-engine';

export interface ScanRecord {
  id: string;
  timestamp: number;
  input: string;
  hasImage: boolean;
  result: ThreatAnalysisResult;
}

const STORAGE_KEY = 'aegis_scan_history';

export function saveScan(
  input: string,
  hasImage: boolean,
  result: ThreatAnalysisResult
): ScanRecord {
  const record: ScanRecord = {
    id: Date.now().toString(36) + Math.random().toString(36).slice(2),
    timestamp: Date.now(),
    input: input.trim() || '[Image only]',
    hasImage,
    result,
  };
  try {
    const existing = getScans();
    const updated = [record, ...existing].slice(0, 100);
    localStorage.setItem(STORAGE_KEY, JSON.stringify(updated));
  } catch {
    // localStorage unavailable (SSR)
  }
  return record;
}

export function getScans(): ScanRecord[] {
  if (typeof window === 'undefined') return [];
  try {
    const data = localStorage.getItem(STORAGE_KEY);
    return data ? JSON.parse(data) : [];
  } catch {
    return [];
  }
}

export function deleteScan(id: string): void {
  try {
    const scans = getScans().filter(s => s.id !== id);
    localStorage.setItem(STORAGE_KEY, JSON.stringify(scans));
  } catch {}
}

export function clearScans(): void {
  try {
    localStorage.removeItem(STORAGE_KEY);
  } catch {}
}

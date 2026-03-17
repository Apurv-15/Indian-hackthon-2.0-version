/**
 * Email Analysis Cache – localStorage-backed cache keyed by Gmail message ID.
 * Prevents redundant AI analysis on page refreshes.
 */

export interface CachedEmailAnalysis {
  riskLevel: string;
  threatType: string;
  confidenceScore: number;
  explanation: string;
  indicators: string[];
  recommendations: string[];
  riskScore?: number;
  detailedScores?: {
    phishingProb: number;
    spamProb: number;
    urlRisk: number;
    sentimentLabel: string;
    sentimentScore: number;
  };
}

interface CacheEntry {
  analysis: CachedEmailAnalysis;
  cachedAt: number;
}

const STORAGE_KEY = 'aegis_email_analysis_cache';
const MAX_ENTRIES = 200;

function readCache(): Record<string, CacheEntry> {
  if (typeof window === 'undefined') return {};
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    return raw ? JSON.parse(raw) : {};
  } catch {
    return {};
  }
}

function writeCache(cache: Record<string, CacheEntry>): void {
  try {
    // FIFO eviction if over limit
    const keys = Object.keys(cache);
    if (keys.length > MAX_ENTRIES) {
      const sorted = keys.sort(
        (a, b) => cache[a].cachedAt - cache[b].cachedAt
      );
      const toRemove = sorted.slice(0, keys.length - MAX_ENTRIES);
      toRemove.forEach((k) => delete cache[k]);
    }
    localStorage.setItem(STORAGE_KEY, JSON.stringify(cache));
  } catch {
    // localStorage unavailable (SSR / quota)
  }
}

/** Get cached analysis for a given email ID. Returns null if not cached. */
export function getCachedAnalysis(
  emailId: string
): CachedEmailAnalysis | null {
  const cache = readCache();
  const entry = cache[emailId];
  return entry?.analysis ?? null;
}

/** Store analysis for a given email ID */
export function setCachedAnalysis(
  emailId: string,
  analysis: CachedEmailAnalysis
): void {
  const cache = readCache();
  cache[emailId] = { analysis, cachedAt: Date.now() };
  writeCache(cache);
}

/** Delete cached analysis for one email (used by Retest) */
export function deleteCachedAnalysis(emailId: string): void {
  const cache = readCache();
  delete cache[emailId];
  writeCache(cache);
}

/** Clear every cached email analysis */
export function clearAllCachedAnalysis(): void {
  try {
    localStorage.removeItem(STORAGE_KEY);
  } catch {}
}

/** Check whether an email has a cached analysis */
export function hasCachedAnalysis(emailId: string): boolean {
  return getCachedAnalysis(emailId) !== null;
}

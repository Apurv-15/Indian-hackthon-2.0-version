export interface ThreatAnalysisResult {
  riskLevel: "Safe" | "Low" | "Medium" | "High" | "Critical";
  threatType: string;
  confidenceScore: number;
  explanation: string;
  indicators: string[];
  recommendations: string[];
}

export async function analyzeThreat(input: string, imageBase64?: string, mimeType?: string): Promise<ThreatAnalysisResult> {
  const response = await fetch('/api/analyze', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ input, imageBase64, mimeType }),
  });

  if (!response.ok) {
    const errorData = await response.json();
    throw new Error(errorData.error || 'Failed to analyze threat');
  }

  return response.json();
}

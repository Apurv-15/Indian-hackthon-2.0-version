import { GoogleGenAI, Type } from "@google/genai";
import { NextResponse } from "next/server";

const ai = new GoogleGenAI({ apiKey: process.env.GEMINI_API_KEY || "" });

export async function POST(req: Request) {
  try {
    const { input, imageBase64, mimeType } = await req.json();
    const model = "gemini-1.5-pro";

    const mediaPart = imageBase64 && mimeType ? [{
      inlineData: {
        data: imageBase64,
        mimeType: mimeType
      }
    }] : [];

    const inputText = input || "[Image provided without text]";

    // --- STAGE 1: External Threat Specialist ---
    const agent1Response = await ai.getGenerativeModel({ 
      model: model,
      systemInstruction: "You are an OSINT and Lead Security Investigator. Identify external red flags, domain reputation, and broad threat patterns.",
    }).generateContent({ 
      contents: [{
        role: "user",
        parts: [
          ...mediaPart,
          { text: `[AGENT 1: EXTERNAL THREAT SPECIALIST]\nAnalyze the reputation and source of this input: "${inputText}".\nFocus on:\n1. URL/Domain reputation (if applicable).\n2. Known phishing patterns or sender spoofing signs.\n3. Metadata analysis of the request.\n\nProvide your initial findings and suspicion level.` }
        ]
      }]
    });

    const agent1Findings = agent1Response.response.text();

    // --- STAGE 2: Internal Forensic Specialist ---
    const agent2Response = await ai.getGenerativeModel({ 
      model: model,
      systemInstruction: "You are a Technical and Forensic Security Analyst. Inspect content, scripts, and psychological tactics for concealed threats.",
    }).generateContent({
      contents: [{
        role: "user",
        parts: [
          ...mediaPart,
          { text: `[AGENT 2: INTERNAL FORENSIC SPECIALIST]\nPrevious Agent Findings: "${agent1Findings}"\n\nNow, deep dive into the content and technical elements of: "${inputText}".\nFocus on:\n1. Psychological triggers, urgency, or malicious intent in the text.\n2. Code-level analysis (scripts, obfuscation, prompt injections).\n3. Payload analysis or deceptive UI patterns.\n\nProvide your technical and internal forensic findings.` }
        ]
      }]
    });

    const agent2Findings = agent2Response.response.text();

    // --- STAGE 3: Consensus Synthesizer ---
    const finalResponse = await ai.getGenerativeModel({ 
      model: model,
      systemInstruction: "You are the Lead Security Architect. You must synthesize multiple specialist reports into a single, high-confidence assessment. You are critical and seek to minimize false positives/negatives.",
      generationConfig: {
        responseMimeType: "application/json",
        responseSchema: {
          type: Type.OBJECT,
          properties: {
            riskLevel: {
              type: Type.STRING,
              enum: ["Safe", "Low", "Medium", "High", "Critical"]
            },
            threatType: { type: Type.STRING },
            confidenceScore: { type: Type.NUMBER },
            explanation: { type: Type.STRING },
            indicators: { type: Type.ARRAY, items: { type: Type.STRING } },
            recommendations: { type: Type.ARRAY, items: { type: Type.STRING } }
          },
          required: ["riskLevel", "threatType", "confidenceScore", "explanation", "indicators", "recommendations"]
        }
      }
    }).generateContent({
      contents: [{
        role: "user",
        parts: [
          ...mediaPart,
          { text: `[AGENT 3: CONSENSUS SYNTHESIZER]\nTeam Findings:\n- External Specialist: "${agent1Findings}"\n- Forensic Specialist: "${agent2Findings}"\n\nInput: "${inputText}"\n\nSynthesize the final report. Act as a Red Team critic first: challenge any assumptions made by the previous agents. Then, provide the final consensus in JSON format.` }
        ]
      }]
    });

    return NextResponse.json(JSON.parse(finalResponse.response.text()));
  } catch (error: any) {
    console.error("Analysis Error:", error);
    return NextResponse.json({ error: error.message }, { status: 500 });
  }
}

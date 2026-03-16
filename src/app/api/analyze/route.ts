import { GoogleGenAI, Type } from "@google/genai";
import { NextResponse } from "next/server";

const ai = new GoogleGenAI({ apiKey: process.env.GEMINI_API_KEY || "" });

export async function POST(req: Request) {
  try {
    const { input, imageBase64, mimeType } = await req.json();
    const modelName = "gemini-1.5-pro";

    const mediaPart = imageBase64 && mimeType ? [{
      inlineData: {
        data: imageBase64,
        mimeType: mimeType
      }
    }] : [];

    const inputText = input || "[Media file provided without text context]";

    // --- STAGE 1: INITIAL SCREENING SPECIALIST ---
    const agent1Response = await ai.models.generateContent({ 
      model: modelName,
      contents: {
        parts: [
          ...mediaPart,
          { text: `[AGENT 1: INITIAL SCREENING]\nPerform an initial screening of this media: "${inputText}".\nFlag any immediate suspicious elements like obvious spectral grids or visual flickering.` }
        ]
      },
      config: {
        systemInstruction: "You are an Initial Media Screening Specialist. Your role is to load/validate media and perform a quick scan for obvious synthetic artifacts or compression anomalies.",
      }
    });

    const agent1Findings = agent1Response.text;

    // --- STAGE 2: DEEPFAKE AV FORENSICS SPECIALIST ---
    const agent2Response = await ai.models.generateContent({ 
      model: modelName,
      contents: {
        parts: [
          ...mediaPart,
          { text: `[AGENT 2: AV FORENSICS SPECIALIST]\nInitial Screen Results: "${agent1Findings}"\n\nPerform a deep diagnostic analysis of the media: "${inputText}".\nProvide detailed findings according to your framework.` }
        ]
      },
      config: {
        systemInstruction: `You are Agent 2 - Deepfake Audio/Video Forensics Specialist. Your role is to analyze uploaded media files for synthetic generation artifacts and impersonation indicators using a multi-layered approach.

## AUDIO Analysis (.mp3, .wav):
1. Spectral Artifacts: Frequency patterns, grid-like artifacts, formant transitions.
2. Temporal Anomalies: Micro-pause durations, robotic rhythm, breathing patterns.
3. Voice Quality: Vocal tract resonance, pitch stability, sibilant artifacts.
4. Background Noise: Ambient floor consistency, splicing signs.

## VIDEO Analysis (.mp4):
1. Facial Micro-expressions: Blinking patterns, asynchronous lip movements, muscle stiffness.
2. Visual Artifacts: Face-boundary inconsistencies, lighting mismatches, temporal flickering.
3. Audio-Visual Sync: Lip-sync accuracy, audio leading/lagging, emotional congruence.
4. Environmental Consistency: Eye reflections, shadow dynamics, depth of field.`,
      }
    });

    const agent2Findings = agent2Response.text;

    // --- STAGE 3: VIDEO-ONLY VISUAL SPECIALIST ---
    const agent3Response = await ai.models.generateContent({ 
      model: modelName,
      contents: {
        parts: [
          ...mediaPart, 
          { text: `[AGENT 3: VISUAL SPECIALIST]\nReview the visual elements of this media: "${inputText}".\nLook for visual-only deepfake indicators that the multi-modal specialist might have mixed with audio cues.` }
        ]
      },
      config: {
        systemInstruction: "You are the Video-Only Visual Specialist. Your role is to EXCLUSIVELY analyze the video frames for spatial and temporal visual artifacts, ignoring the audio entirely. Focus on face-swapping boundaries, lighting inconsistencies on skin, and frame-to-frame pixel flickering.",
      }
    });

    const agent3Findings = agent3Response.text;

    // --- STAGE 4: FORENSIC CONSENSUS SYNTHESIZER ---
    const finalResponse = await ai.models.generateContent({ 
      model: modelName,
      contents: {
        parts: [
          ...mediaPart,
          { text: `[AGENT 4: SYNTHESIZER]\nTeam Findings:\n- Screening: "${agent1Findings}"\n- AV Forensics: "${agent2Findings}"\n- Visual-Only: "${agent3Findings}"\n\nMedia Context: "${inputText}"\n\nSynthesize the final forensic report in JSON format.` }
        ]
      },
      config: {
        systemInstruction: "You are the Forensic Consensus Synthesizer. You must synthesize multiple specialist reports into a single, high-confidence forensic assessment. You are critical and seek to minimize false positives.",
        responseMimeType: "application/json",
        responseSchema: {
          type: Type.OBJECT,
          properties: {
            riskLevel: {
              type: Type.STRING,
              enum: ["Safe", "Low", "Medium", "High", "Critical"]
            },
            threatType: { type: Type.STRING, description: "Deepfake Detection / Synthetic Media" },
            confidenceScore: { type: Type.NUMBER },
            explanation: { type: Type.STRING, description: "Detailed forensic reasoning citing specific specialist findings (Agent 2 and 3)." },
            indicators: { type: Type.ARRAY, items: { type: Type.STRING } },
            recommendations: { type: Type.ARRAY, items: { type: Type.STRING } }
          },
          required: ["riskLevel", "threatType", "confidenceScore", "explanation", "indicators", "recommendations"]
        }
      }
    });

    return NextResponse.json(JSON.parse(finalResponse.text));
  } catch (error: any) {
    console.error("Analysis Error:", error);
    return NextResponse.json({ error: error.message }, { status: 500 });
  }
}

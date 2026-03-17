import { NextResponse } from 'next/server';

export const dynamic = 'force-dynamic';

const PYTHON_BRIDGE_URL = process.env.PYTHON_BRIDGE_URL || 'http://127.0.0.1:5001/analyze';

/**
 * POST /api/emails/analyze
 * Body: { input: string }
 * Forwards a single email's content to the Python AI bridge and returns the analysis.
 */
export async function POST(req) {
  try {
    const { input } = await req.json();

    if (!input || typeof input !== 'string' || !input.trim()) {
      return NextResponse.json({ error: 'No input provided' }, { status: 400 });
    }

    let bridgeResponse;
    try {
      console.log('Forwarding to AI Space:', PYTHON_BRIDGE_URL);
      
      // Hugging Face Gradio API expects {"data": [arg1, arg2...]}
      const body = JSON.stringify({ data: [input.trim()] });
      
      bridgeResponse = await fetch(PYTHON_BRIDGE_URL, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: body,
        signal: AbortSignal.timeout(25000), // AI models can be slow on first load
      });
    } catch (fetchError) {
      console.error('AI Space unreachable:', fetchError.message);
      return NextResponse.json(
        { error: 'AI Analysis engine is sleeping or starting up. Please wait a moment.' },
        { status: 503 }
      );
    }

    const json = await bridgeResponse.json();
    
    // Gradio returns result in {"data": [actual_result_here]}
    const data = json.data ? json.data[0] : json;

    if (!bridgeResponse.ok || data.error) {
      console.error('AI Space error:', data.error || json);
      return NextResponse.json(
        { error: data.error || 'Analysis failed' },
        { status: 500 }
      );
    }

    return NextResponse.json(data);
  } catch (error) {
    console.error('Email analyze error:', error);
    return NextResponse.json({ error: error.message }, { status: 500 });
  }
}

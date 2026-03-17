import { NextResponse } from 'next/server';

export const dynamic = 'force-dynamic';

const PYTHON_BRIDGE_URL = 'http://127.0.0.1:5001/analyze';

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
      bridgeResponse = await fetch(PYTHON_BRIDGE_URL, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ input: input.trim() }),
        signal: AbortSignal.timeout(15000),
      });
    } catch (fetchError) {
      console.error('Bridge unreachable:', fetchError.message);
      return NextResponse.json(
        { error: 'Analysis engine is not running.' },
        { status: 503 }
      );
    }

    const data = await bridgeResponse.json();

    if (!bridgeResponse.ok || data.error) {
      console.error('Bridge error:', data.error);
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

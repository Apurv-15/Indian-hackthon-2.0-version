import { NextResponse } from "next/server";

const PYTHON_BRIDGE_URL = "http://127.0.0.1:5001/analyze";

export async function POST(req: Request) {
  try {
    const { input } = await req.json();

    if (!input || typeof input !== "string" || !input.trim()) {
      return NextResponse.json({ error: "No input provided" }, { status: 400 });
    }

    // Forward request to the persistent Python model server
    let bridgeResponse: Response;
    try {
      bridgeResponse = await fetch(PYTHON_BRIDGE_URL, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ input: input.trim() }),
        // 30 s timeout (first cold-start may need a bit more during dev)
        signal: AbortSignal.timeout(30_000),
      });
    } catch (fetchError: any) {
      console.error("Bridge unreachable:", fetchError.message);
      return NextResponse.json(
        {
          error:
            "Analysis engine is not running. Please start it with: python3 ai_agent/bridge.py",
        },
        { status: 503 }
      );
    }

    const data = await bridgeResponse.json();

    if (!bridgeResponse.ok || data.error) {
      console.error("Bridge error:", data.error);
      return NextResponse.json(
        { error: data.error || "Analysis failed" },
        { status: 500 }
      );
    }

    return NextResponse.json(data);
  } catch (error: any) {
    console.error("Server Error:", error);
    return NextResponse.json({ error: error.message }, { status: 500 });
  }
}

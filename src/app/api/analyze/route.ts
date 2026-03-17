import { NextResponse } from "next/server";

const PYTHON_BRIDGE_URL = process.env.PYTHON_BRIDGE_URL || "http://127.0.0.1:5001/analyze";

export async function POST(req: Request) {
  try {
    const { input } = await req.json();

    if (!input || typeof input !== "string" || !input.trim()) {
      return NextResponse.json({ error: "No input provided" }, { status: 400 });
    }

    // Forward request to the persistent Python model server
    let bridgeResponse: Response;
    try {
      console.log('Scanning via AI Space:', PYTHON_BRIDGE_URL);
      const body = JSON.stringify({ data: [input.trim()] });

      bridgeResponse = await fetch(PYTHON_BRIDGE_URL, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: body,
        signal: AbortSignal.timeout(30_000),
      });
    } catch (fetchError: any) {
      console.error("AI Space unreachable:", fetchError.message);
      return NextResponse.json(
        {
          error:
            "The AI Engine is currently starting up (Cold Start). Please wait 30 seconds and try again.",
        },
        { status: 503 }
      );
    }

    const json = await bridgeResponse.json();
    const data = json.data ? json.data[0] : json;

    if (!bridgeResponse.ok || data.error) {
      console.error("AI Space Error:", data.error || json);
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

import { createUIMessageStream, createUIMessageStreamResponse } from "ai";

const BACKEND_BASE =
  process.env.INTERNAL_API_URL ||
  process.env.NEXT_PUBLIC_API_URL ||
  "http://127.0.0.1:8000/api/v1";

export async function POST(req: Request) {
  try {
    const body = await req.json();
    const { messages, incidentId } = body;

    if (!incidentId) {
      return new Response(
        JSON.stringify({ error: "Missing required parameter: incidentId" }),
        { status: 400, headers: { "Content-Type": "application/json" } },
      );
    }

    // Extract the latest user question from messages
    let lastUserMessage = "";
    if (Array.isArray(messages)) {
      for (let i = messages.length - 1; i >= 0; i--) {
        const msg = messages[i];
        if (msg.role === "user") {
          if (typeof msg.content === "string") {
            lastUserMessage = msg.content;
            break;
          }
          if (Array.isArray(msg.parts)) {
            const textPart = msg.parts.find(
              (p: { type: string; text?: string }) => p.type === "text",
            );
            if (textPart?.text) {
              lastUserMessage = textPart.text;
              break;
            }
          }
        }
      }
    }

    // Call PacketSage backend ask endpoint
    const backendRes = await fetch(
      `${BACKEND_BASE}/incidents/${encodeURIComponent(incidentId)}/ask`,
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ question: lastUserMessage || undefined }),
      },
    );

    if (!backendRes.ok) {
      let errorText = `Backend error ${backendRes.status}`;
      try {
        const errJson = await backendRes.json();
        errorText = errJson.detail || JSON.stringify(errJson);
      } catch {
        // use default errorText
      }

      return new Response(JSON.stringify({ error: errorText }), {
        status: backendRes.status,
        headers: { "Content-Type": "application/json" },
      });
    }

    const data: {
      answer: string;
      cited_flow_ids: number[];
      invalid_citations: number[];
      provider: string;
      model: string;
    } = await backendRes.json();

    const textToStream = data.answer || "";
    const textBlockId = `block-${Date.now()}`;

    // Create standard AI SDK UI message stream
    const stream = createUIMessageStream({
      execute: async ({ writer }) => {
        writer.write({ type: "start" });

        // Optional metadata chunk for provider/citations
        writer.write({
          type: "data-metadata",
          data: {
            provider: data.provider,
            model: data.model,
            cited_flow_ids: data.cited_flow_ids || [],
            invalid_citations: data.invalid_citations || [],
          },
        });

        writer.write({ type: "text-start", id: textBlockId });

        // Tokenize text into words/whitespace for real-time streaming illusion
        const chunks = textToStream.match(/\S+|\s+/g) || [textToStream];
        for (const chunk of chunks) {
          writer.write({
            type: "text-delta",
            id: textBlockId,
            delta: chunk,
          });
          // Non-blocking micro-delay for smooth text streaming
          await new Promise((r) => setTimeout(r, 12));
        }

        writer.write({ type: "text-end", id: textBlockId });
        writer.write({ type: "finish" });
      },
    });

    return createUIMessageStreamResponse({ stream });
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : "Internal Server Error";
    return new Response(JSON.stringify({ error: msg }), {
      status: 500,
      headers: { "Content-Type": "application/json" },
    });
  }
}

import { createMcpHandler } from "mcp-handler";
import { dispatchWebhook, webhookInputShape, type WebhookInput } from "@/lib/webhook";
import { validateAuth, createUnauthorizedResponse } from "@/lib/auth";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";
export const maxDuration = 30;

/**
 * Underlying MCP handler initializing server tools.
 */
const mcpHandler = createMcpHandler((server) => {
  server.registerTool(
    "dispatch_webhook",
    {
      title: "Dispatch Webhook",
      description:
        "Dispatches an HTTP GET or POST request to a target webhook URL with optional JSON payload and HMAC-SHA256 signature verification.",
      inputSchema: webhookInputShape,
    },
    async (args: WebhookInput) => {
      const result = await dispatchWebhook(args);
      return {
        content: [
          {
            type: "text" as const,
            text: JSON.stringify(result, null, 2),
          },
        ],
        isError: !result.success,
      };
    }
  );
});

export async function GET(request: Request): Promise<Response> {
  const auth = validateAuth(request);
  if (!auth.authorized) {
    return createUnauthorizedResponse();
  }
  return mcpHandler(request);
}

export async function POST(request: Request): Promise<Response> {
  const auth = validateAuth(request);
  if (!auth.authorized) {
    return createUnauthorizedResponse();
  }
  return mcpHandler(request);
}

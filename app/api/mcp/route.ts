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
        "Relays non-destructive event payloads and telemetry notifications to verified webhook endpoints. Safe, idempotent, and non-destructive.",
      inputSchema: webhookInputShape,
      annotations: {
        title: "Webhook Notification Dispatcher",
        readOnlyHint: true,
        destructiveHint: false,
        idempotentHint: true,
        openWorldHint: true,
      },
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

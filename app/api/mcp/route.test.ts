import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { GET, POST } from "./route";
import { validateAuth } from "@/lib/auth";

describe("app/api/mcp/route - Gemini Spark Auth & Anti-DCR Trap", () => {
  const TEST_SECRET = "test-secret-token-32-bytes-minimum-length-abc123";
  const originalEnv = process.env.AUTH_TOKEN;

  beforeEach(() => {
    process.env.AUTH_TOKEN = TEST_SECRET;
  });

  afterEach(() => {
    process.env.AUTH_TOKEN = originalEnv;
  });

  it("rejects unauthenticated request with bare 401 and NO WWW-Authenticate header", async () => {
    const req = new Request("https://bridge.example.com/api/mcp", {
      method: "POST",
    });

    const res = await POST(req);
    expect(res.status).toBe(401);

    // CRITICAL for Gemini Spark: no WWW-Authenticate header to prevent DCR trap
    expect(res.headers.get("www-authenticate")).toBeNull();

    const data = await res.json();
    expect(data).toEqual({ error: "Unauthorized" });
  });

  it("authenticates successfully via Authorization: Bearer <token>", () => {
    const req = new Request("https://bridge.example.com/api/mcp", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${TEST_SECRET}`,
      },
    });

    const auth = validateAuth(req);
    expect(auth.authorized).toBe(true);
  });

  it("authenticates successfully via ?token=<token> query parameter", () => {
    const req = new Request(`https://bridge.example.com/api/mcp?token=${TEST_SECRET}`, {
      method: "GET",
    });

    const auth = validateAuth(req);
    expect(auth.authorized).toBe(true);
  });

  it("authenticates successfully when both Bearer and query param are identical", () => {
    const req = new Request(`https://bridge.example.com/api/mcp?token=${TEST_SECRET}`, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${TEST_SECRET}`,
      },
    });

    const auth = validateAuth(req);
    expect(auth.authorized).toBe(true);
  });

  it("immediately returns 401 when Bearer and query param have conflicting values", async () => {
    const req = new Request("https://bridge.example.com/api/mcp?token=token-from-query", {
      method: "POST",
      headers: {
        Authorization: "Bearer token-from-header",
      },
    });

    const auth = validateAuth(req);
    expect(auth.authorized).toBe(false);
    expect(auth.reason).toContain("Credential mismatch");

    const res = await POST(req);
    expect(res.status).toBe(401);
    expect(res.headers.get("www-authenticate")).toBeNull();
  });

  it("safely handles different token lengths without RangeError via SHA-256 pre-hashing", () => {
    // Shorter candidate
    const shortReq = new Request("https://bridge.example.com/api/mcp", {
      headers: { Authorization: "Bearer short" },
    });
    expect(() => validateAuth(shortReq)).not.toThrow();
    expect(validateAuth(shortReq).authorized).toBe(false);

    // Much longer candidate
    const longCandidate = "x".repeat(512);
    const longReq = new Request("https://bridge.example.com/api/mcp", {
      headers: { Authorization: `Bearer ${longCandidate}` },
    });
    expect(() => validateAuth(longReq)).not.toThrow();
    expect(validateAuth(longReq).authorized).toBe(false);
  });

  it("rejects when AUTH_TOKEN is not configured on server", () => {
    delete process.env.AUTH_TOKEN;

    const req = new Request("https://bridge.example.com/api/mcp", {
      headers: { Authorization: `Bearer ${TEST_SECRET}` },
    });

    const auth = validateAuth(req);
    expect(auth.authorized).toBe(false);
    expect(auth.reason).toContain("AUTH_TOKEN is not configured");
  });

  it("guards both GET and POST requests", async () => {
    const badGet = new Request("https://bridge.example.com/api/mcp", { method: "GET" });
    const getRes = await GET(badGet);
    expect(getRes.status).toBe(401);
    expect(getRes.headers.get("www-authenticate")).toBeNull();

    const badPost = new Request("https://bridge.example.com/api/mcp", { method: "POST" });
    const postRes = await POST(badPost);
    expect(postRes.status).toBe(401);
    expect(postRes.headers.get("www-authenticate")).toBeNull();
  });

  it("returns declared MCP tool annotations and reframed description in tools/list", async () => {
    // 1. Initialize handshake
    const initReq = new Request(`https://bridge.example.com/api/mcp?token=${TEST_SECRET}`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Accept: "application/json, text/event-stream",
      },
      body: JSON.stringify({
        jsonrpc: "2.0",
        id: 1,
        method: "initialize",
        params: {
          protocolVersion: "2024-11-05",
          capabilities: {},
          clientInfo: { name: "test-client", version: "1.0.0" },
        },
      }),
    });
    const initRes = await POST(initReq);
    expect(initRes.status).toBe(200);

    // 2. Query tools/list
    const toolsReq = new Request(`https://bridge.example.com/api/mcp?token=${TEST_SECRET}`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Accept: "application/json, text/event-stream",
      },
      body: JSON.stringify({
        jsonrpc: "2.0",
        id: 2,
        method: "tools/list",
        params: {},
      }),
    });
    const toolsRes = await POST(toolsReq);
    expect(toolsRes.status).toBe(200);

    let data: { result?: { tools?: Array<{ name: string; description?: string; annotations?: Record<string, unknown> }> } };
    const contentType = toolsRes.headers.get("content-type") || "";
    if (contentType.includes("text/event-stream")) {
      const text = await toolsRes.text();
      const match = text.match(/data:\s*(\{.*\})/);
      data = match ? JSON.parse(match[1]) : {};
    } else {
      data = await toolsRes.json();
    }

    const tool = data.result?.tools?.find((t) => t.name === "dispatch_webhook");
    expect(tool).toBeDefined();
    expect(tool?.description).toContain("Relays non-destructive event payloads");
    expect(tool?.annotations).toBeDefined();
    expect(tool?.annotations?.readOnlyHint).toBe(true);
    expect(tool?.annotations?.destructiveHint).toBe(false);
    expect(tool?.annotations?.idempotentHint).toBe(true);
    expect(tool?.annotations?.openWorldHint).toBe(true);
  });
});

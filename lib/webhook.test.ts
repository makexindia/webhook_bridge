import { describe, it, expect, beforeEach, vi } from "vitest";
import crypto from "node:crypto";
import {
  isPrivateIPv4,
  isPrivateIPv6,
  isHostnameAllowed,
  getAllowedDomains,
  validateWebhookUrl,
  sanitizeOutboundHeaders,
  computeCanonicalHmacSignature,
  readStreamWithLimit,
  extractResponseHeaders,
  dispatchWebhook,
  webhookInputSchema,
} from "./webhook";

describe("lib/webhook - SSRF Guard & IP Classification", () => {
  it("correctly identifies private/restricted IPv4 addresses", () => {
    // Loopback
    expect(isPrivateIPv4("127.0.0.1")).toBe(true);
    expect(isPrivateIPv4("127.255.255.254")).toBe(true);

    // Current network
    expect(isPrivateIPv4("0.0.0.0")).toBe(true);

    // Private RFC 1918
    expect(isPrivateIPv4("10.0.0.1")).toBe(true);
    expect(isPrivateIPv4("10.254.12.3")).toBe(true);
    expect(isPrivateIPv4("172.16.0.1")).toBe(true);
    expect(isPrivateIPv4("172.31.255.255")).toBe(true);
    expect(isPrivateIPv4("192.168.1.1")).toBe(true);

    // Carrier-Grade NAT (100.64.0.0/10)
    expect(isPrivateIPv4("100.64.0.1")).toBe(true);
    expect(isPrivateIPv4("100.127.255.255")).toBe(true);
    expect(isPrivateIPv4("100.128.0.1")).toBe(false);

    // Cloud Metadata & Link-Local (169.254.0.0/16)
    expect(isPrivateIPv4("169.254.169.254")).toBe(true);
    expect(isPrivateIPv4("169.254.1.1")).toBe(true);

    // Multicast & Reserved
    expect(isPrivateIPv4("224.0.0.1")).toBe(true);
    expect(isPrivateIPv4("240.0.0.1")).toBe(true);

    // Public IPv4
    expect(isPrivateIPv4("8.8.8.8")).toBe(false);
    expect(isPrivateIPv4("1.1.1.1")).toBe(false);
    expect(isPrivateIPv4("142.250.190.46")).toBe(false);
  });

  it("correctly identifies private/restricted IPv6 addresses", () => {
    expect(isPrivateIPv6("::1")).toBe(true);
    expect(isPrivateIPv6("0:0:0:0:0:0:0:1")).toBe(true);
    expect(isPrivateIPv6("::")).toBe(true);
    expect(isPrivateIPv6("fc00::1")).toBe(true);
    expect(isPrivateIPv6("fd12:3456:789a::1")).toBe(true);
    expect(isPrivateIPv6("fe80::1")).toBe(true);
    expect(isPrivateIPv6("::ffff:127.0.0.1")).toBe(true);
    expect(isPrivateIPv6("::ffff:169.254.169.254")).toBe(true);

    // Public IPv6
    expect(isPrivateIPv6("2607:f8b0:4005:805::200e")).toBe(false);
  });
});

describe("lib/webhook - Domain Allowlist & Hostname Matching", () => {
  const allowed = ["makex.in", "api.stripe.com"];

  it("matches exact domains", () => {
    expect(isHostnameAllowed("makex.in", allowed)).toBe(true);
    expect(isHostnameAllowed("api.stripe.com", allowed)).toBe(true);
  });

  it("matches dot-prefixed subdomains", () => {
    expect(isHostnameAllowed("api.makex.in", allowed)).toBe(true);
    expect(isHostnameAllowed("sub.api.makex.in", allowed)).toBe(true);
    expect(isHostnameAllowed("webhooks.api.stripe.com", allowed)).toBe(true);
  });

  it("strictly rejects collision/suffix spoofing domains (e.g. evilmakex.in)", () => {
    expect(isHostnameAllowed("evilmakex.in", allowed)).toBe(false);
    expect(isHostnameAllowed("notmakex.in", allowed)).toBe(false);
    expect(isHostnameAllowed("fakeapi.stripe.com", allowed)).toBe(false);
  });

  it("throws initialization error if ALLOWED_WEBHOOK_DOMAINS is missing in production", () => {
    vi.stubEnv("NODE_ENV", "production");
    vi.stubEnv("ALLOWED_WEBHOOK_DOMAINS", "");

    try {
      expect(() => getAllowedDomains()).toThrow(
        /ALLOWED_WEBHOOK_DOMAINS is mandatory in production/
      );
    } finally {
      vi.unstubAllEnvs();
    }
  });
});

describe("lib/webhook - URL & DNS Validation", () => {
  beforeEach(() => {
    process.env.ALLOWED_WEBHOOK_DOMAINS = "makex.in,example.com";
  });

  it("rejects non-HTTPS URLs", async () => {
    await expect(validateWebhookUrl("http://makex.in/webhook")).rejects.toThrow(
      /Only HTTPS webhooks are permitted/
    );
  });

  it("rejects localhost and loopback hostnames", async () => {
    await expect(validateWebhookUrl("https://localhost/webhook")).rejects.toThrow(
      /forbidden loopback address/
    );
    await expect(validateWebhookUrl("https://127.0.0.1/webhook")).rejects.toThrow(
      /forbidden loopback address/
    );
  });

  it("rejects unlisted domains", async () => {
    await expect(validateWebhookUrl("https://attacker.com/webhook")).rejects.toThrow(
      /is not in ALLOWED_WEBHOOK_DOMAINS/
    );
  });

  it("rejects domains that resolve to internal/private IPs", async () => {
    const mockLookup = vi.fn().mockResolvedValue([
      { address: "169.254.169.254", family: 4 },
    ]);

    await expect(
      validateWebhookUrl("https://makex.in/webhook", { dnsLookup: mockLookup })
    ).rejects.toThrow(/resolved to restricted IP '169.254.169.254'/);
  });

  it("approves valid HTTPS URL resolving to public IP", async () => {
    const mockLookup = vi.fn().mockResolvedValue([
      { address: "93.184.216.34", family: 4 },
    ]);

    const url = await validateWebhookUrl("https://makex.in/webhook?id=123", {
      dnsLookup: mockLookup,
    });
    expect(url.protocol).toBe("https:");
    expect(url.hostname).toBe("makex.in");
  });
});

describe("lib/webhook - Header Sanitization", () => {
  it("strips forbidden headers case-insensitively", () => {
    const input = {
      Host: "evil.com",
      "content-length": "12345",
      Connection: "close",
      "transfer-encoding": "chunked",
      Authorization: "Bearer target-api-key",
      "X-Custom-Client": "gemini-spark",
    };

    const sanitized = sanitizeOutboundHeaders(input);
    expect(sanitized).toEqual({
      authorization: "Bearer target-api-key",
      "x-custom-client": "gemini-spark",
    });
  });
});

describe("lib/webhook - Canonical HMAC-SHA256 Signing", () => {
  it("correctly constructs canonical string and HMAC hex digest", () => {
    const timestamp = "1720000000000";
    const method = "POST";
    const canonicalUrl = "https://api.makex.in/v1/events";
    const serializedBody = JSON.stringify({ event: "order_created", amount: 100 });
    const secret = "test-secret-key-12345";

    const bodyHash = crypto.createHash("sha256").update(serializedBody, "utf8").digest("hex");
    const canonicalString = `${timestamp}\n${method}\n${canonicalUrl}\n${bodyHash}`;
    const expectedSig = crypto.createHmac("sha256", secret).update(canonicalString, "utf8").digest("hex");

    const result = computeCanonicalHmacSignature({
      timestamp,
      method,
      canonicalUrl,
      serializedBody,
      secret,
    });

    expect(result.signature).toBe(expectedSig);
    expect(result.bodyHash).toBe(bodyHash);
  });

  it("correctly computes canonical HMAC with raw string payload", () => {
    const timestamp = "1720000000000";
    const method = "POST";
    const canonicalUrl = "https://api.makex.in/v1/raw";
    const serializedBody = "raw string event text";
    const secret = "test-secret-key-12345";

    const bodyHash = crypto.createHash("sha256").update(serializedBody, "utf8").digest("hex");
    const canonicalString = `${timestamp}\n${method}\n${canonicalUrl}\n${bodyHash}`;
    const expectedSig = crypto.createHmac("sha256", secret).update(canonicalString, "utf8").digest("hex");

    const result = computeCanonicalHmacSignature({
      timestamp,
      method,
      canonicalUrl,
      serializedBody,
      secret,
    });

    expect(result.signature).toBe(expectedSig);
    expect(result.bodyHash).toBe(bodyHash);
  });
});

describe("lib/webhook - Memory-Safe Stream Capping (2,048 Bytes)", () => {
  it("consumes payloads <= 2,048 bytes without truncation", async () => {
    const sampleText = "A".repeat(1024);
    const stream = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(new TextEncoder().encode(sampleText));
        controller.close();
      },
    });

    const result = await readStreamWithLimit(stream, 2048);
    expect(result.truncated).toBe(false);
    expect(result.text).toBe(sampleText);
    expect(result.text.length).toBe(1024);
  });

  it("truncates payloads > 2,048 bytes at exactly 2,048 bytes and cancels reader", async () => {
    let cancelCalled = false;
    const largeChunk = new Uint8Array(4096).fill(66); // 'B' * 4096

    const stream = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(largeChunk);
      },
      cancel() {
        cancelCalled = true;
      },
    });

    const result = await readStreamWithLimit(stream, 2048);
    expect(result.truncated).toBe(true);
    expect(result.text.length).toBe(2048);
    expect(result.text).toBe("B".repeat(2048));
    expect(cancelCalled).toBe(true);
  });

  it("preserves multibyte UTF-8 integrity across boundaries", async () => {
    // Emojis: 4 bytes per emoji (e.g. 🔥 is 4 bytes: 0xf0 0x9f 0x94 0xa5)
    const emoji = "🔥";
    const emojiBytes = new TextEncoder().encode(emoji);
    expect(emojiBytes.length).toBe(4);

    const stream = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(emojiBytes);
        controller.close();
      },
    });

    const result = await readStreamWithLimit(stream, 2048);
    expect(result.text).toBe("🔥");
    expect(result.truncated).toBe(false);
  });
});

describe("lib/webhook - Response Headers Normalization", () => {
  it("limits recorded headers to 20 normalized lowercase keys", () => {
    const headers = new Headers();
    for (let i = 0; i < 25; i++) {
      headers.set(`X-Custom-Header-${i}`, `value-${i}`);
    }

    const recorded = extractResponseHeaders(headers, 20);
    expect(Object.keys(recorded).length).toBe(20);
    expect(recorded["x-custom-header-0"]).toBe("value-0");
  });
});

describe("lib/webhook - dispatchWebhook integration", () => {
  beforeEach(() => {
    process.env.ALLOWED_WEBHOOK_DOMAINS = "makex.in";
    process.env.WEBHOOK_HMAC_SECRET = "super-secret-hmac";
  });

  it("dispatches POST request with canonical HMAC headers and redirect: error", async () => {
    let capturedUrl = "";
    let capturedInit: RequestInit | undefined;

    const mockFetch = vi.fn().mockImplementation(async (url: string, init: RequestInit) => {
      capturedUrl = url;
      capturedInit = init;
      const responseStream = new ReadableStream<Uint8Array>({
        start(controller) {
          controller.enqueue(new TextEncoder().encode('{"status":"ok"}'));
          controller.close();
        },
      });

      return new Response(responseStream, {
        status: 200,
        statusText: "OK",
        headers: { "Content-Type": "application/json" },
      });
    });

    const mockLookup = vi.fn().mockResolvedValue([{ address: "93.184.216.34", family: 4 }]);

    const result = await dispatchWebhook(
      {
        url: "https://makex.in/api/v1/webhook",
        method: "POST",
        headers: {
          Authorization: "Bearer ext-token",
          Host: "spoofed.com", // should be stripped
        },
        payload: { action: "sync" },
        timeoutMs: 5000,
      },
      {
        customFetch: mockFetch as unknown as typeof fetch,
        dnsLookup: mockLookup,
      }
    );

    expect(result.success).toBe(true);
    expect(result.status).toBe(200);
    expect(result.body).toBe('{"status":"ok"}');
    expect(result.truncated).toBe(false);

    // Verify outbound call properties
    expect(capturedUrl).toBe("https://makex.in/api/v1/webhook");
    expect(capturedInit?.method).toBe("POST");
    expect(capturedInit?.redirect).toBe("error");

    const sentHeaders = capturedInit?.headers as Record<string, string>;
    expect(sentHeaders.authorization).toBe("Bearer ext-token");
    expect(sentHeaders.host).toBeUndefined();
    expect(sentHeaders["X-Timestamp"]).toBeDefined();
    expect(sentHeaders["X-Signature-SHA256"]).toBeDefined();
    expect(sentHeaders["content-type"]).toBe("application/json; charset=utf-8");
  });

  it("defaults Content-Type to application/json; charset=utf-8 for object payload", async () => {
    let capturedInit: RequestInit | undefined;
    const mockFetch = vi.fn().mockImplementation(async (_url: string, init: RequestInit) => {
      capturedInit = init;
      return new Response(new ReadableStream({ start(c) { c.close(); } }), { status: 200 });
    });
    const mockLookup = vi.fn().mockResolvedValue([{ address: "93.184.216.34", family: 4 }]);

    await dispatchWebhook(
      {
        url: "https://makex.in/api/v1/notify",
        method: "POST",
        payload: { title: "Alert", priority: 4, tags: ["warning"] },
        timeoutMs: 5000,
      },
      {
        customFetch: mockFetch as unknown as typeof fetch,
        dnsLookup: mockLookup,
      }
    );

    const sentHeaders = capturedInit?.headers as Record<string, string>;
    expect(sentHeaders["content-type"]).toBe("application/json; charset=utf-8");
    expect(capturedInit?.body).toBe(JSON.stringify({ title: "Alert", priority: 4, tags: ["warning"] }));
  });

  it("preserves case-insensitive user Content-Type override without duplicate headers", async () => {
    let capturedInit: RequestInit | undefined;
    const mockFetch = vi.fn().mockImplementation(async (_url: string, init: RequestInit) => {
      capturedInit = init;
      return new Response(new ReadableStream({ start(c) { c.close(); } }), { status: 200 });
    });
    const mockLookup = vi.fn().mockResolvedValue([{ address: "93.184.216.34", family: 4 }]);

    await dispatchWebhook(
      {
        url: "https://makex.in/api/v1/custom",
        method: "POST",
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
        },
        payload: { key: "value" },
        timeoutMs: 5000,
      },
      {
        customFetch: mockFetch as unknown as typeof fetch,
        dnsLookup: mockLookup,
      }
    );

    const sentHeaders = capturedInit?.headers as Record<string, string>;
    expect(sentHeaders["content-type"]).toBe("application/x-www-form-urlencoded");
    // Ensure no capitalized duplicate exists
    expect(sentHeaders["Content-Type"]).toBeUndefined();
  });

  it("defaults Content-Type to text/plain; charset=utf-8 and passes raw string for string payload", async () => {
    let capturedInit: RequestInit | undefined;
    const mockFetch = vi.fn().mockImplementation(async (_url: string, init: RequestInit) => {
      capturedInit = init;
      return new Response(new ReadableStream({ start(c) { c.close(); } }), { status: 200 });
    });
    const mockLookup = vi.fn().mockResolvedValue([{ address: "93.184.216.34", family: 4 }]);

    await dispatchWebhook(
      {
        url: "https://makex.in/api/v1/raw",
        method: "POST",
        payload: "Raw plain text webhook message",
        timeoutMs: 5000,
      },
      {
        customFetch: mockFetch as unknown as typeof fetch,
        dnsLookup: mockLookup,
      }
    );

    const sentHeaders = capturedInit?.headers as Record<string, string>;
    expect(sentHeaders["content-type"]).toBe("text/plain; charset=utf-8");
    expect(capturedInit?.body).toBe("Raw plain text webhook message");
  });

  it("allows user Content-Type override on string payload", async () => {
    let capturedInit: RequestInit | undefined;
    const mockFetch = vi.fn().mockImplementation(async (_url: string, init: RequestInit) => {
      capturedInit = init;
      return new Response(new ReadableStream({ start(c) { c.close(); } }), { status: 200 });
    });
    const mockLookup = vi.fn().mockResolvedValue([{ address: "93.184.216.34", family: 4 }]);

    await dispatchWebhook(
      {
        url: "https://makex.in/api/v1/raw-json",
        method: "POST",
        headers: {
          "content-type": "application/json",
        },
        payload: '{"preSerialized":true}',
        timeoutMs: 5000,
      },
      {
        customFetch: mockFetch as unknown as typeof fetch,
        dnsLookup: mockLookup,
      }
    );

    const sentHeaders = capturedInit?.headers as Record<string, string>;
    expect(sentHeaders["content-type"]).toBe("application/json");
    expect(capturedInit?.body).toBe('{"preSerialized":true}');
  });

  it("handles GET request without body", async () => {
    let capturedInit: RequestInit | undefined;

    const mockFetch = vi.fn().mockImplementation(async (_url: string, init: RequestInit) => {
      capturedInit = init;
      return new Response(new ReadableStream({ start(c) { c.close(); } }), { status: 200 });
    });

    const mockLookup = vi.fn().mockResolvedValue([{ address: "93.184.216.34", family: 4 }]);

    const result = await dispatchWebhook(
      {
        url: "https://makex.in/health",
        method: "GET",
        timeoutMs: 5000,
      },
      {
        customFetch: mockFetch as unknown as typeof fetch,
        dnsLookup: mockLookup,
      }
    );

    expect(result.success).toBe(true);
    expect(capturedInit?.body).toBeUndefined();
    expect(capturedInit?.method).toBe("GET");
  });

  it("handles outbound fetch errors gracefully", async () => {
    const mockFetch = vi.fn().mockRejectedValue(new Error("Network connection reset"));
    const mockLookup = vi.fn().mockResolvedValue([{ address: "93.184.216.34", family: 4 }]);

    const result = await dispatchWebhook(
      {
        url: "https://makex.in/fail",
        method: "POST",
        timeoutMs: 5000,
      },
      {
        customFetch: mockFetch as unknown as typeof fetch,
        dnsLookup: mockLookup,
      }
    );

    expect(result.success).toBe(false);
    expect(result.error).toContain("Network connection reset");
  });
});

describe("lib/webhook - webhookInputSchema validation", () => {
  it("validates good inputs", () => {
    const parsed = webhookInputSchema.parse({
      url: "https://example.com/webhook",
      method: "POST",
      payload: { hello: "world" },
      timeoutMs: 15000,
    });

    expect(parsed.url).toBe("https://example.com/webhook");
    expect(parsed.method).toBe("POST");
    expect(parsed.timeoutMs).toBe(15000);
  });

  it("validates string payload successfully", () => {
    const parsed = webhookInputSchema.parse({
      url: "https://example.com/webhook",
      method: "POST",
      payload: "plain text notification",
    });

    expect(parsed.payload).toBe("plain text notification");
  });

  it("defaults method to POST and timeout to 10000", () => {
    const parsed = webhookInputSchema.parse({
      url: "https://example.com/webhook",
    });

    expect(parsed.method).toBe("POST");
    expect(parsed.timeoutMs).toBe(10000);
  });

  it("rejects timeoutMs < 1000 or > 25000", () => {
    expect(() =>
      webhookInputSchema.parse({
        url: "https://example.com/webhook",
        timeoutMs: 500,
      })
    ).toThrow();

    expect(() =>
      webhookInputSchema.parse({
        url: "https://example.com/webhook",
        timeoutMs: 30000,
      })
    ).toThrow();
  });
});
